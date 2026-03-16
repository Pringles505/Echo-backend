const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { customAlphabet } = require('nanoid');
const path = require('path');
const fs = require('fs');
const {
  OPK_LOW_WATERMARK,
  OPK_TARGET_COUNT,
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  normalizeOneTimePreKeysPayload,
  computeOpkReplenishNeeded,
  dedupeIncomingOpks,
  capToRemainingCapacity,
  estimateOpkCountAfterConsume,
} = require('./opkPolicy');

const OPK_BUNDLE_LIMITS = Object.freeze({
  // Counts all getPreKeyBundle requests, regardless of whether an OPK is actually consumed.
  requesterRequests: { max: 60, windowMs: 60_000 },
  pairRequests: { max: 10, windowMs: 60_000 },
  targetRequests: { max: 60, windowMs: 60_000 },

  // Applies only when the target currently has OPKs available (checked via User.exists).
  requesterConsumes: { max: 30, windowMs: 60_000 },
  targetConsumes: { max: 30, windowMs: 60_000 },

  // Prevent rapid re-fetch from draining multiple OPKs for the same requester/target pair.
  pairLeaseMs: 60_000,
});

const opkLimiterState = {
  reqByRequester: new Map(),
  reqByPair: new Map(),
  reqByTarget: new Map(),
  consumeByRequester: new Map(),
  consumeByTarget: new Map(),
  leaseByPair: new Map(),
};

function fixedWindowTake(map, key, max, windowMs, cost = 1) {
  const now = Date.now();
  const k = String(key ?? '');
  if (!k) return { allowed: false, retryAfterMs: windowMs };

  let state = map.get(k);
  if (!state || state.resetAt <= now) {
    state = { count: 0, resetAt: now + windowMs };
  }

  if (state.count + cost > max) {
    map.set(k, state);
    return { allowed: false, retryAfterMs: Math.max(0, state.resetAt - now) };
  }

  state.count += cost;
  map.set(k, state);
  return { allowed: true, retryAfterMs: 0 };
}

function getSocketIp(socket) {
  const raw = socket?.handshake?.headers?.['x-forwarded-for'];
  if (typeof raw === 'string' && raw.trim()) return raw.split(',')[0].trim();
  return String(socket?.handshake?.address ?? '');
}

// Load environment variables. When running via `node --test`, prefer `.env.test` if present.
const dotenv = require('dotenv');
const { type } = require('os');
const envTestPath = path.join(__dirname, '.env.test');
const runningNodeTest = process.argv.includes('--test');
if (runningNodeTest && fs.existsSync(envTestPath)) {
  dotenv.config({ path: envTestPath });
} else {
  dotenv.config();
}

// Helper to save image and return URL
async function saveProfilePicture(base64Image, userId) {
  const uploadDir = path.join(__dirname, 'uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
  }
  const filename = `${userId}-${Date.now()}.png`;
  const filePath = path.join(uploadDir, filename);
  const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, '');
  fs.writeFileSync(filePath, base64Data, { encoding: 'base64' });
  return `/uploads/${filename}`;
}

async function createCallEventMessage({ callId, status, duration = 0 }) {
  try {
    const call = await Call.findOne({ callId });
    if (!call) {
      console.log('Call not found for event message:', callId);
      return null;
    }

    // Check if a call event message already exists for this callId
    const existingCallEvent = await Message.findOne({
      messageType: 'call_event',
      'callData.callId': callId
    });

    if (existingCallEvent) {
      console.log('⚠️ Call event message already exists for callId:', callId);
      return existingCallEvent;
    }

    const sender = await User.findOne({ id: call.callerId });
    if (!sender) {
      console.log('Sender not found:', call.callerId);
      return null;
    }

    const message = new Message({
      messageType: 'call_event',
      callData: {
        status,
        callType: call.callType,
        duration,
        callerId: call.callerId,
        receiverId: call.receiverId,
        callId: call.callId
      },
      userId: call.callerId,
      targetUserId: call.receiverId,
      username: sender.username,
      seenStatus: false,
      messageNumber: 0, // Call events don't need message numbers
      is_initial: false,
      payload: '', // No encryption for call events
      publicEphemeralKey: ''
    });

    await message.save();
    console.log('✅ Call event message saved:', status);

    const messageWithProfile = {
      ...message.toObject(),
      profileImage: sender.profilePicture || null,
      timestamp: message.createdAt,
    };

    // Emit to both users
    const room = [call.callerId, call.receiverId].sort().join('_');
    io.to(room).emit('newMessage', messageWithProfile);

    // Also emit directly to users who are NOT in the room
    const callerSocketId = userSocketMap[call.callerId];
    const receiverSocketId = userSocketMap[call.receiverId];

    if (callerSocketId) {
      const callerSocket = io.sockets.sockets.get(callerSocketId);
      if (!callerSocket || !callerSocket.rooms.has(room)) {
        io.to(callerSocketId).emit('newMessage', messageWithProfile);
      }
    }
    if (receiverSocketId) {
      const receiverSocket = io.sockets.sockets.get(receiverSocketId);
      if (!receiverSocket || !receiverSocket.rooms.has(room)) {
        io.to(receiverSocketId).emit('newMessage', messageWithProfile);
      }
    }

    return message;
  } catch (err) {
    console.error('Error creating call event message:', err);
    return null;
  }
}

const userSocketMap = {};

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://chat-tuah-frontend.vercel.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'https://chat-tuah-frontend.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('/health', (_req, res) => res.sendStatus(200));

const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('Error connecting to MongoDB', err);
});

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  username: { type: String, unique: true },
  hashedPassword: String,
  friends: [String],
  publicIdentityKeyX25519: String,
  publicIdentityKeyEd25519: String,
  signedPreKey: String,
  signature: String,
  signedPreKeyId: { type: Number, default: 0 },
  oneTimePreKeys: [
    {
      opkId: String,
      opkPub: String,
    },
  ],
  aboutme: { type: String, default: '' },
  profilePicture: { type: String, default: '' },
});

const messageSchema = new mongoose.Schema({
  is_initial: Boolean,
  payload: String,
  nonce: String,
  userId: String,
  targetUserId: String,
  conversationKey: { type: String, default: null },
  username: String,
  messageNumber: Number,
  sendingNumber: Number,
  previousSendingNumber: Number,
  publicEphemeralKey: String,
  spkId: { type: mongoose.Schema.Types.Mixed, default: null },
  opkId: { type: String, default: null },
  seenStatus: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },

  messageType: {
    type: String,
    enum: ['text', 'image', 'tenor', 'call_event'],
    default: 'text'
  },
  callData: {
    status: {
      type: String,
      enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed']
    },
    callType: String,
    duration: Number,
    callerId: String,
    receiverId: String,
    callId: String
  },

  conversationType: {
    type: String,
    enum: ['direct', 'group'],
    default: 'direct'
  },

  // Group message fields 

  groupId: { type: String, default: null, index: true },
  seq: { type: Number, default: null, index: true, groupId: 1, seq: 1 },

  // Only MLS fields
  epoch: { type: Number, default: null },
  senderLeafIndex: { type: Number, default: null },
  contentType: { type: String, enum: ['application', 'commit', 'welcome', null], default: null },
  headerB64: { type: String, default: null },
  ciphertextB64: { type: String, default: null },


});

const messageSequenceSchema = new mongoose.Schema({
  conversationKey: { type: String, required: true, unique: true, index: true },
  participants: { type: [String], default: [] },
  lastMessageNumber: { type: Number, default: -1 },
  lastSenderId: { type: String, default: null },
  updatedAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
});

const opkRequestLogSchema = new mongoose.Schema({
  requesterId: { type: String, index: true },
  targetUserId: { type: String, index: true },
  pairKey: { type: String, index: true },
  ip: String,
  userAgent: String,

  outcome: String, // e.g. success, lease_reuse, rate_limited_*
  retryAfterMs: { type: Number, default: 0 },

  opkConsumed: { type: Boolean, default: false },
  opkId: { type: String, default: null },

  createdAt: { type: Date, default: Date.now, index: true },
});

// Keep logs for 30 days (MongoDB TTL index).
opkRequestLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 });

const calls = new mongoose.Schema({
  callId: { type: String, unique: true },
  callerId: String,
  receiverId: String,
  startedAt: { type: Date, default: Date.now },
  endedAt: { type: Date, default: null },
  callType: { type: String, default: 'video' },
  status: {
    type: String,
    enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed'],
    default: 'ringing',
  },
  duration: { type: Number, default: 0 },

});

const groupSchema = new mongoose.Schema({
  groupId: { type: String, unique: true, index: true },
  name: String,
  createdAt: { type: Date, default: Date.now },
  createdBy: String,

  mlsEnabled: { type: Boolean, default: false },
  epoch: { type: Number, default: 0 },
  cipherSuite: { type: String, default: null },
});

const groupMemberSchema = new mongoose.Schema({
  groupId: { type: String, index: true },
  userId: { type: String, index: true },
  role: { type: String, enum: ['admin', 'member'], default: 'member' },
  joinedAt: { type: Date, default: Date.now },

  leafIndex: { type: Number, default: null },
  credential: { type: mongoose.Schema.Types.Mixed, default: null },
  status: { type: String, enum: ['active', 'removed'], default: 'active' },
});

const groupSequenceSchema = new mongoose.Schema({
  groupId: { type: String, required: true, unique: true, index: true },
  lastSequenceNumber: { type: Number, default: -1 },
  updatedAt: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);
const User = mongoose.model('User', userSchema);
const MessageSequence = mongoose.model('MessageSequence', messageSequenceSchema);
const OpkRequestLog = mongoose.model('OpkRequestLog', opkRequestLogSchema);
const Call = mongoose.model('Call', calls);
const Group = mongoose.model('Group', groupSchema);
const GroupMember = mongoose.model('GroupMember', groupMemberSchema);
const GroupSequence = mongoose.model('GroupSequence', groupSequenceSchema);

const keyPackageSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  initKeyB64: { type: String, required: true },
  updatedAt: { type: Date, default: Date.now },
});
const KeyPackage = mongoose.model('KeyPackage', keyPackageSchema);

async function syncKeyPackageIndexes() {
  try {
    const droppedIndexes = await KeyPackage.syncIndexes();
    console.log('[MLS] KeyPackage indexes synced', droppedIndexes);
  } catch (err) {
    console.error('[MLS] Failed to sync KeyPackage indexes:', err);
  }
}

if (mongoose.connection.readyState === 1) {
  void syncKeyPackageIndexes();
} else {
  mongoose.connection.once('open', () => {
    void syncKeyPackageIndexes();
  });
}

function makeConversationKey(userA, userB) {
  return [String(userA ?? ''), String(userB ?? '')].sort().join('_');
}

async function ensureConversationSequence(conversationKey, userA, userB) {
  const existing = await MessageSequence.findOne({ conversationKey }).lean();
  if (existing) return existing;

  const a = String(userA ?? '');
  const b = String(userB ?? '');

  // Initialize from existing messages so we don't accidentally allow duplicates after deployment.
  const lastMsg = await Message.findOne({
    $or: [
      { userId: a, targetUserId: b },
      { userId: b, targetUserId: a },
    ],
    // Only initialize from real encrypted chat messages (exclude call_event entries which use messageNumber=0).
    messageType: 'text',
    messageNumber: { $type: 'number' },
  })
    .sort({ messageNumber: -1 })
    .select({ messageNumber: 1 })
    .lean();

  const last = Number.isFinite(lastMsg?.messageNumber) ? lastMsg.messageNumber : -1;
  const participants = [a, b].filter(Boolean).sort();

  try {
    return await MessageSequence.create({
      conversationKey,
      participants,
      lastMessageNumber: last,
      updatedAt: new Date(),
      createdAt: new Date(),
    });
  } catch (err) {
    // Another request likely created it concurrently.
    if (err?.code === 11000) {
      return await MessageSequence.findOne({ conversationKey }).lean();
    }
    throw err;
  }
}

async function ensureGroupSequence(groupId) {
  const gid = String(groupId ?? '');
  if (!gid) throw new Error('Missing groupId');

  const existing = await GroupSequence.findOne({ groupId: gid }).lean();
  if (existing) return existing;

  try {
    return await GroupSequence.create({
      groupId: gid,
      lastSequenceNumber: -1,
      updatedAt: new Date(),
    });
  } catch (err) {
    if (err?.code === 11000) {
      return await GroupSequence.findOne({ groupId: gid }).lean();
    }
    throw err;
  }
}

function logOpkRequest(entry) {
  try {
    // Fire-and-forget; don't block the socket handler on DB logging.
    OpkRequestLog.create(entry).catch((err) => {
      console.warn('OPK request logging failed:', err?.message ?? err);
    });
  } catch (err) {
    console.warn('OPK request logging failed:', err?.message ?? err);
  }
}

const authenticate = (socket, next) => {
  const token = socket.handshake?.auth?.token;

  if (!token) {
    console.warn('No token provided, allowing unauthenticated access for login/register');
    socket.user = null;
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.warn('Invalid/expired token; rejecting connection:', err?.name ?? err);
      return next(new Error('unauthorized'));
    }

    if (!decoded?.id) {
      console.warn('JWT verified but missing user id; rejecting connection');
      return next(new Error('unauthorized'));
    }

    userSocketMap[decoded.id] = socket.id;
    console.log(`User ${decoded.username} is mapped to socket ${socket.id}`);
    socket.user = decoded;
    return next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {

  const PUBLIC_EVENTS = new Set(['login', 'register']);

  socket.use((packet, next) => {
    // Pre-socket gate: everything except login/register requires authentication.
    const eventName = packet?.[0];
    const maybeAck = packet?.[packet.length - 1];
    const ack = typeof maybeAck === 'function' ? maybeAck : null;

    if (PUBLIC_EVENTS.has(eventName)) return next();
    if (!socket.user?.id) {
      if (ack) ack({ success: false, error: 'unauthorized' });
      return next(new Error('unauthorized'));
    }
    return next();
  });


  console.log(`A user connected with socket ID: ${socket.id}`);

  const requestOpkReplenishmentIfLow = async (targetUserId, currentCountOverride = null) => {
    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return;

    const currentCount =
      typeof currentCountOverride === 'number'
        ? currentCountOverride
        : (await User.findOne({ id: targetUserId }, { oneTimePreKeys: 1 }))?.oneTimePreKeys?.length ?? 0;

    const needed = computeOpkReplenishNeeded(currentCount);
    if (needed <= 0) return;

    io.to(targetSocketId).emit('replenishOPKs', { needed });
  };

  const emitEventToGroupMembers = async ({ groupId, eventName, payload, excludeUserIds = [] }) => {
    const groupIdStr = String(groupId ?? '');
    const exclude = new Set(excludeUserIds.map((userId) => String(userId ?? '')).filter(Boolean));
    const members = await GroupMember.find({ groupId: groupIdStr }, { userId: 1 }).lean();

    let deliveredCount = 0;
    for (const member of members) {
      const memberId = String(member?.userId ?? '');
      if (!memberId || exclude.has(memberId)) continue;

      const memberSocketId = userSocketMap[memberId];
      if (!memberSocketId) continue;

      io.to(memberSocketId).emit(eventName, payload);
      deliveredCount += 1;
    }

    return deliveredCount;
  };

  const allocateNextGroupSequence = async (groupId) => {
    const groupIdStr = String(groupId ?? '');
    await ensureGroupSequence(groupIdStr);

    const updated = await GroupSequence.findOneAndUpdate(
      { groupId: groupIdStr },
      {
        $inc: { lastSequenceNumber: 1 },
        $set: { updatedAt: new Date() },
      },
      { new: true }
    );

    if (!updated) {
      throw new Error(`Failed to allocate group sequence for ${groupIdStr}`);
    }

    return updated.lastSequenceNumber;
  };

  const persistGroupArtifactMessage = async ({
    groupId,
    senderUserId,
    senderUsername,
    targetUserId = null,
    epoch = null,
    senderLeafIndex = null,
    contentType,
    artifact,
  }) => {
    const groupIdStr = String(groupId ?? '');
    const seq = await allocateNextGroupSequence(groupIdStr);

    const message = new Message({
      payload: JSON.stringify(artifact),
      nonce: `artifact:${contentType}:${seq}`,
      userId: String(senderUserId ?? ''),
      targetUserId: targetUserId ? String(targetUserId) : null,
      conversationKey: null,
      username: senderUsername,
      seenStatus: false,
      messageNumber: null,
      sendingNumber: null,
      previousSendingNumber: null,
      publicEphemeralKey: null,
      spkId: null,
      opkId: null,
      messageType: 'text',
      conversationType: 'group',
      groupId: groupIdStr,
      seq,
      epoch: Number.isInteger(epoch) ? epoch : null,
      senderLeafIndex: Number.isInteger(senderLeafIndex) ? senderLeafIndex : null,
      contentType,
      headerB64: null,
      ciphertextB64: null,
    });

    await message.save();
    return { message, seq };
  };

  if (socket.user?.id) {
    // Notify other clients that user is online
    socket.broadcast.emit('userOnline', { userId: socket.user.id });

    // Send the full list of online users to the connecting client
    socket.emit('onlineUsersList', { onlineUsers: Object.keys(userSocketMap) });

    // Push any pending MLS welcomes to the newly-connected user
    // (si el usuario esta offline que no se pierda los welcomes)
    const authedId = String(socket.user.id);
    Message.find({
      conversationType: 'group',
      contentType: 'welcome',
      targetUserId: authedId,
    }).lean().then((stored) => {
      for (const msg of stored) {
        try {
          const welcome = JSON.parse(msg.payload);
          socket.emit('groupWelcome', { groupId: msg.groupId, welcome });
        } catch { /* skip malformed */ }
      }
    }).catch((err) => {
      console.error('[MLS] Error pushing pending welcomes on connect:', err);
    });
  }


  socket.on('getOnlineUsers', (callback) => {
    callback({ onlineUsers: Object.keys(userSocketMap) });
  });

  socket.on('fetchUsername', async (userId, callback) => {
    console.log('Fetching username for user:', userId);
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        callback({ success: true, username: user.username });
      } else {
        callback({ success: false, error: 'User not found' });
      }
    } catch (error) {
      console.error('Error fetching username:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('ready', async ({ targetUserId }) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !targetUserId) return;

    console.log(`User ${authedUserId} is opening chat with ${targetUserId}`);

    // Create a private room between authed user and target user
    const room = [authedUserId, targetUserId].sort().join('_');
    socket.join(room);

    try {
      const message = await Message.find({
        $or: [
          { userId: authedUserId, targetUserId },
          { userId: targetUserId, targetUserId: authedUserId },
        ],
      }).sort({ createdAt: 1 });

      console.log(`Sending ${message.length} messages to User ${authedUserId} ↔ ${targetUserId}`);

      // Message is emitted to users in room and no one else
      io.to(room).emit('newMessage', message);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  });

  // Get the SignedPreKey Array (PreyKey + Signature) for XEdDSA 
  socket.on('getSignedPreKey', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching SignedPreKey for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) {
        console.error('❌ User not found');
        return callback({ success: false, error: 'User not found' });
      }
      console.log('✅ Found PreKey:', user.signedPreKey);
      console.log('✅ Found Signature:', user.signature);

      // Return the SignedPreKey as an array [publicPreKey, signature]
      callback({
        success: true,
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
      });
    } catch (error) {
      console.error('❌ Error fetching SignedPreKey:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  // Get publicIdentityKey in Montgomery format
  socket.on('getPublicIdentityKeyX25519', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching PublicIdentityKeyX25519 for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) {
        console.error('❌ User not found');
        return callback({ success: false, error: 'User not found' });
      }
      console.log('✅ Found publicIdentityKeyX25519:', user.publicIdentityKeyX25519);
      callback({ success: true, publicIdentityKeyX25519: user.publicIdentityKeyX25519 });
    } catch (error) {
      console.error('❌ Error fetching publicIdentityKeyX25519:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  // Get publicIdentityKey in Edwards format
  socket.on('getPublicIdentityKeyEd25519', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching publicIdentityKeyEd25519 for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) {
        console.error('❌ User not found');
        return callback({ success: false, error: 'User not found' });
      }
      console.log('✅ Found publicIdentityKeyEd25519:', user.publicIdentityKeyEd25519);
      callback({ success: true, publicIdentityKeyEd25519: user.publicIdentityKeyEd25519 });
    } catch (error) {
      console.error('❌ Error fetching publicIdentityKeyEd25519:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getPreKeyBundle', async ({ targetUserId }, callback) => {
    const requesterId = socket.user?.id;
    const targetId = String(targetUserId ?? '');
    const ip = getSocketIp(socket);
    const userAgent = String(socket?.handshake?.headers?.['user-agent'] ?? '');
    const pairKey = `${requesterId ?? ''}:${targetId}`;

    console.log(`🔍 Fetching PreKeyBundle: requester=${requesterId} target=${targetId}`);

    if (!requesterId) {
      logOpkRequest({ requesterId: null, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'unauthorized' });
      return callback?.({ success: false, error: 'Unauthorized' });
    }

    if (!targetId) {
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'invalid_target' });
      return callback?.({ success: false, error: 'Missing targetUserId' });
    }

    const req1 = fixedWindowTake(
      opkLimiterState.reqByRequester,
      requesterId,
      OPK_BUNDLE_LIMITS.requesterRequests.max,
      OPK_BUNDLE_LIMITS.requesterRequests.windowMs
    );
    if (!req1.allowed) {
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'rate_limited_requester_requests',
        retryAfterMs: req1.retryAfterMs,
      });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req1.retryAfterMs });
    }

    const req2 = fixedWindowTake(
      opkLimiterState.reqByPair,
      pairKey,
      OPK_BUNDLE_LIMITS.pairRequests.max,
      OPK_BUNDLE_LIMITS.pairRequests.windowMs
    );
    if (!req2.allowed) {
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'rate_limited_pair_requests',
        retryAfterMs: req2.retryAfterMs,
      });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req2.retryAfterMs });
    }

    const req3 = fixedWindowTake(
      opkLimiterState.reqByTarget,
      targetId,
      OPK_BUNDLE_LIMITS.targetRequests.max,
      OPK_BUNDLE_LIMITS.targetRequests.windowMs
    );
    if (!req3.allowed) {
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'rate_limited_target_requests',
        retryAfterMs: req3.retryAfterMs,
      });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req3.retryAfterMs });
    }

    const lease = opkLimiterState.leaseByPair.get(pairKey);
    if (lease && lease.expiresAt > Date.now()) {
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'lease_reuse',
        opkConsumed: Boolean(lease?.bundle?.opk),
        opkId: lease?.bundle?.opk?.opkId ?? null,
      });
      return callback?.({ success: true, bundle: lease.bundle });
    }

    try {
      const targetHasOpk = await User.exists({
        id: targetId,
        'oneTimePreKeys.0': { $exists: true },
      });

      if (targetHasOpk) {
        const c1 = fixedWindowTake(
          opkLimiterState.consumeByRequester,
          requesterId,
          OPK_BUNDLE_LIMITS.requesterConsumes.max,
          OPK_BUNDLE_LIMITS.requesterConsumes.windowMs
        );
        const c2 = fixedWindowTake(
          opkLimiterState.consumeByTarget,
          targetId,
          OPK_BUNDLE_LIMITS.targetConsumes.max,
          OPK_BUNDLE_LIMITS.targetConsumes.windowMs
        );

        if (!c1.allowed || !c2.allowed) {
          const retryAfterMs = Math.max(c1.retryAfterMs ?? 0, c2.retryAfterMs ?? 0);
          logOpkRequest({
            requesterId,
            targetUserId: targetId,
            pairKey,
            ip,
            userAgent,
            outcome: 'rate_limited_opk_consumption',
            retryAfterMs,
          });
          return callback?.({
            success: false,
            error: 'OPK consumption rate limited',
            retryAfterMs,
          });
        }
      }

      // Attempt to atomically pop the first OPK (if any) and return the pre-update doc.
      const userWithOpk = await User.findOneAndUpdate(
        { id: targetId, 'oneTimePreKeys.0': { $exists: true } },
        { $pop: { oneTimePreKeys: -1 } },
        { new: false }
      );

      let user = userWithOpk;
      let consumedOpk = null;
      let estimatedNewOpkCount = null;

      if (userWithOpk) {
        consumedOpk = userWithOpk.oneTimePreKeys?.[0] ?? null;
        estimatedNewOpkCount = estimateOpkCountAfterConsume(userWithOpk.oneTimePreKeys?.length ?? 0);
        console.log('✅ Consumed OPK:', consumedOpk?.opkId ?? null);
      } else {
        // No OPK to consume; still return the bundle without OPK.
        user = await User.findOne({ id: targetId });
      }

      if (!user) {
        console.error('❌ User not found');
        logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'target_not_found' });
        return callback({ success: false, error: 'User not found' });
      }

      // If the target user is online and running low on OPKs, ask them to upload more.
      const currentCount =
        typeof estimatedNewOpkCount === 'number'
          ? estimatedNewOpkCount
          : (user.oneTimePreKeys?.length ?? 0);
      requestOpkReplenishmentIfLow(targetId, currentCount).catch(() => { });

      const bundle = {
        publicIdentityKeyX25519: user.publicIdentityKeyX25519,
        publicIdentityKeyEd25519: user.publicIdentityKeyEd25519,
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
        opk: consumedOpk
          ? { opkId: consumedOpk.opkId, opkPub: consumedOpk.opkPub ?? consumedOpk.publicKey }
          : null,
      };

      opkLimiterState.leaseByPair.set(pairKey, {
        expiresAt: Date.now() + OPK_BUNDLE_LIMITS.pairLeaseMs,
        bundle,
      });

      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'success',
        opkConsumed: Boolean(bundle.opk),
        opkId: bundle.opk?.opkId ?? null,
      });

      callback({ success: true, bundle });
    } catch (error) {
      console.error('❌ Error fetching PreKeyBundle:', error);
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'error' });
      callback({ success: false, error: 'Internal server error' });
    }
  });

  // Upload/append additional PUBLIC OPKs for the currently-authenticated user.
  socket.on('uploadOneTimePreKeys', async ({ oneTimePreKeys }, callback) => {
    try {
      const authedUserId = socket.user?.id;
      if (!authedUserId) {
        return callback?.({ success: false, error: 'Unauthorized' });
      }

      const bounded = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_UPLOAD_MAX);
      if (bounded.length === 0) {
        return callback?.({ success: false, error: 'No OPKs provided' });
      }

      const user = await User.findOne({ id: authedUserId });
      if (!user) {
        return callback?.({ success: false, error: 'User not found' });
      }

      const existingOpks = user.oneTimePreKeys ?? [];
      const unique = dedupeIncomingOpks(existingOpks, bounded);
      const capped = capToRemainingCapacity(existingOpks.length, unique, OPK_MAX_STORED);

      if (capped.length > 0) {
        await User.updateOne(
          { id: authedUserId },
          { $push: { oneTimePreKeys: { $each: capped } } }
        );
      }

      callback?.({ success: true, stored: capped.length });
    } catch (error) {
      console.error('❌ Error uploading OPKs:', error);
      callback?.({ success: false, error: 'Internal server error' });
    }
  });

  // Returns the current PUBLIC OPK count for the authenticated user.
  socket.on('getOpkStatus', async (_, callback) => {
    try {
      const authedUserId = socket.user?.id;
      if (!authedUserId) {
        return callback?.({ success: false, error: 'Unauthorized' });
      }

      const user = await User.findOne({ id: authedUserId }, { oneTimePreKeys: 1 });
      const currentCount = user?.oneTimePreKeys?.length ?? 0;
      const needed = computeOpkReplenishNeeded(currentCount);
      callback?.({ success: true, currentCount, needed });
    } catch (error) {
      console.error('❌ Error fetching OPK status:', error);
      callback?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('disconnect', () => {
    console.log(`🔴User with socket ID ${socket.id} disconnected.🔴`);

    for (const userId in userSocketMap) {
      if (userSocketMap[userId] === socket.id) {
        delete userSocketMap[userId];

        // Notify other clients user is offline
        socket.broadcast.emit('userOffline', { userId });

        break;
      }
    }
  });


  socket.on('register', async (data, callback) => {
    const { username, password, keyBundle, aboutme, profilePicture } = data;
    const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;
    const [signedPreKey, signature] = publicSignedPreKey;

    console.log('Received register:', data);
    console.log('Public Identity Key X25519:', publicIdentityKeyX25519);
    console.log('Public Identity Key Ed25519:', publicIdentityKeyEd25519);

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
      const id = nanoid();

      // Normalize OPKs from client
      const normalizedOpks = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_MAX_STORED);

      const user = new User({
        id,
        username,
        hashedPassword,
        publicIdentityKeyX25519,
        publicIdentityKeyEd25519,
        signedPreKey,
        signature,
        signedPreKeyId: 0,
        oneTimePreKeys: normalizedOpks,
        aboutme: typeof aboutme === 'string' ? aboutme : '',
        profilePicture: typeof profilePicture === 'string' ? profilePicture : '',
      });

      await user.save();
      console.log('User saved:', user);
      callback({ success: true, userId: id });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
        // Duplicate username error
        callback({ success: false, error: "Username already taken" });
      } else {
        console.error('Error saving user:', err);
        callback({ success: false, error: "Registration failed" });
      }
    }
  });

  socket.on('messageSeen', async (data) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const { targetUserId } = data;
    console.log("Message from ", authedUserId, " seen by ", targetUserId);

    try {
      // Log the query and update
      console.log('Updating messages with query:', { authedUserId, targetUserId, seenStatus: false });
      console.log('Update operation:', { $set: { seenStatus: true } });

      const result = await Message.updateMany(
        { userId: targetUserId, targetUserId: authedUserId, seenStatus: false },
        { $set: { seenStatus: true } }
      );

      console.log('Updated messages seenStatus:', result);

      const senderSocketId = userSocketMap[targetUserId];
      if (senderSocketId) {
        io.to(senderSocketId).emit('messageSeenUpdate', { userId: authedUserId, targetUserId });
        console.log(`Notified sender ${targetUserId} with socket id ${senderSocketId} about seen status update`);
      }

    } catch (err) {
      console.error('Error updating seenStatus:', err);
    }
  });

  socket.on('login', async (data, callback) => {
    const { username, password } = data;
    console.log('Received login:', data);

    try {
      const user = await User.findOne({ username });
      if (!user) {
        console.log('User not found');
        return callback({ success: false, error: 'Invalid username or password' });
      }
      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) {
        console.log('Password mismatch');
        return callback({ success: false, error: 'Invalid username or password' });
      }
      console.log('Password match');

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );
      console.log('Generated Token:', token);

      callback({ success: true, token, userId: user.id });
    } catch (err) {
      console.error('Error during login:', err);
      callback({ success: false, error: 'Login failed' });
    }
  });

  socket.on('checkIfMessagesExist', async (data, callback) => {
    const authedUserId = socket.user?.id;
    const { targetUserId } = data ?? {};
    if (!authedUserId || !targetUserId) return callback?.({ success: false });

    console.log('Checking if messages exist for:', { userId: authedUserId, targetUserId });

    try {
      const message_1 = await Message.findOne({ userId: authedUserId, targetUserId });
      const message_2 = await Message.findOne({ userId: targetUserId, targetUserId: authedUserId });
      if (message_1 || message_2) {
        console.log('Messages exist for this user pair');
        callback({ success: true });
      } else {
        console.log('No messages found for this user pair');
        callback({ success: false });
      }
    } catch (err) {
      console.error('Error checking messages:', err);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getLatestMessageNumber', async (data, callback) => {
    const authedUserId = socket.user?.id;
    const { targetUserId } = data ?? {};
    if (!authedUserId || !targetUserId) {
      return callback?.({ success: false, messageNumber: 0 });
    }

    try {
      const conversationKey = makeConversationKey(authedUserId, targetUserId);
      const seq = await ensureConversationSequence(conversationKey, authedUserId, targetUserId);
      const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;
      callback({ success: true, messageNumber: last });
    } catch (err) {
      console.error('Error:', err);
      callback({
        success: false,
        messageNumber: 0  // Fallback value
      });
    }
  });

  socket.on('newMessage', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const ack = (payload) => {
      if (typeof callback === 'function') callback(payload);
    };

    const {
      is_initial, payload, nonce, targetUserId,
      messageNumber, sendingNumber, previousSendingNumber,
      publicEphemeralKey, spkId, opkId,
    } = data;

    const targetUserIdStr = String(targetUserId ?? '');
    const incomingNumber = Number(messageNumber);

    if ((!payload) || !authedUserId || !targetUserIdStr) {
      console.error('Missing fields in message data:', { payload, authedUserId, targetUserId: targetUserIdStr, messageNumber, is_initial });
      ack({ success: false, error: 'Missing required fields' });
      return;
    }

    if (!Number.isSafeInteger(incomingNumber) || incomingNumber < 0) {
      ack({ success: false, error: 'Invalid messageNumber' });
      return;
    }

    const conversationKey = makeConversationKey(authedUserId, targetUserIdStr);

    console.log('Saving message:', { payload, authedUserId, targetUserId: targetUserIdStr, messageNumber: incomingNumber, is_initial, publicEphemeralKey });

    try {
      // Fetch sender's profile information (and ensure the authenticated user exists).
      const sender = await User.findOne({ id: authedUserId });
      if (!sender) {
        console.error('Sender not found:', authedUserId);
        ack({ success: false, error: 'Sender not found' });
        return;
      }

      await ensureConversationSequence(conversationKey, authedUserId, targetUserIdStr);

      // Conversation-wide monotonic enforcement: messageNumber must be exactly last + 1.
      const updated = await MessageSequence.findOneAndUpdate(
        { conversationKey, lastMessageNumber: incomingNumber - 1 },
        { $set: { lastMessageNumber: incomingNumber, lastSenderId: authedUserId, updatedAt: new Date() } },
        { new: true }
      );

      if (!updated) {
        const seq = await MessageSequence.findOne({ conversationKey }).lean();
        const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;

        if (incomingNumber <= last) {
          ack({ success: false, error: 'replay_detected', lastAccepted: last });
          return;
        }

        // This is a "jump" (incomingNumber > last + 1). Reject so an attacker can't lock the conversation by jumping ahead.
        ack({ success: false, error: 'out_of_sync', lastAccepted: last });
        return;
      }

      const username = sender.username;
      const message = new Message({
        is_initial,
        payload,
        nonce,
        userId: authedUserId,
        targetUserId: targetUserIdStr,
        conversationKey,
        username,
        seenStatus: false,
        messageNumber: incomingNumber,
        sendingNumber,
        previousSendingNumber,
        publicEphemeralKey,
        spkId: spkId ?? null,
        opkId: opkId ?? null,
        conversationType: 'direct',
      });

      await message.save();
      console.log('Message successfully saved:', message);

      // Create consistent room name
      const room = [authedUserId, targetUserIdStr].sort().join('_');

      // Enhanced message object with sender profile info
      const messageWithProfile = {
        ...message.toObject(),
        profileImage: sender.profilePicture || null,
        timestamp: message.createdAt,
      };

      // Emit to the room (for users who have the chat open)
      io.to(room).emit('newMessage', messageWithProfile);

      // Also notify the target user directly if they are NOT in the room
      // (i.e., they don't have this chat open but are online)
      const targetSocketId = userSocketMap[targetUserIdStr];
      if (targetSocketId) {
        const targetSocket = io.sockets.sockets.get(targetSocketId);
        if (!targetSocket || !targetSocket.rooms.has(room)) {
          console.log(`📨 Sending notification to ${targetUserIdStr} (socket: ${targetSocketId})`);
          io.to(targetSocketId).emit('newMessage', messageWithProfile);
        }
      } else {
        console.log(`❌ User ${targetUserIdStr} is offline`);
      }

      ack({ success: true });
    } catch (err) {
      console.error('Error saving message:', err);
      // Best-effort rollback: if we advanced the sequence but failed to persist/emit, allow retry with the same number.
      try {
        await MessageSequence.updateOne(
          { conversationKey, lastMessageNumber: incomingNumber },
          { $set: { lastMessageNumber: incomingNumber - 1, updatedAt: new Date() } }
        );
      } catch { }
      ack({ success: false, error: 'Error saving message' });
    }
  });

  socket.on('createGroup', async ({ name, memberIds, mlsEnabled, cipherSuite }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return cb?.({ success: false, error: 'Group name is required' });
    }
    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      return cb?.({ success: false, error: 'At least one member is required' });
    }

    const wantsMls = mlsEnabled === true;
    const normalizedCipherSuite = wantsMls
      ? (typeof cipherSuite === 'string' && cipherSuite.trim().length > 0
        ? cipherSuite.trim()
        : 'MLS-MVP/X25519_AES256GCM_SHA256')
      : null;

    const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
    const authedUserIdStr = String(authedUserId);
    const normalizedMemberIds = [...new Set(memberIds.map((m) => String(m ?? '')).filter(Boolean))].filter(
      (id) => id !== authedUserIdStr
    );

    if (normalizedMemberIds.length === 0) {
      return cb?.({ success: false, error: 'At least one member is required' });
    }

    const emitToUser = (targetUserId, eventName, payload) => {
      const socketId = userSocketMap[String(targetUserId)];
      if (socketId) io.to(socketId).emit(eventName, payload);
    };

    const nowIso = new Date().toISOString();

    let groupId = null;

    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = nanoid();
        try {
          await Group.create({
            groupId: candidate,
            name,
            createdBy:
              authedUserIdStr,
            createdAt: new Date(),
            mlsEnabled: wantsMls,
            epoch: 0,
            cipherSuite: normalizedCipherSuite,
          });
          groupId = candidate;
          break;
        } catch (err) {
          if (err?.code === 11000) continue;
          throw err;
        }
      }

      if (!groupId) {
        return cb?.({ success: false, error: 'Failed to allocate group id' });
      }

      await ensureGroupSequence(groupId);

      // Add the creator as an admin member
      await GroupMember.create({
        groupId,
        userId: authedUserIdStr,
        role: 'admin',
        joinedAt: new Date(),
        leafIndex: 0,
        status: 'active'
      });

      for (const [index, memberId] of normalizedMemberIds.entries()) {

        // Add each member to the group
        await GroupMember.create({
          groupId,
          userId: memberId,
          role: 'member',
          joinedAt: new Date(),
          leafIndex: index + 1,
          status: 'active'
        });

        // Emit event to each member about the new group 
        emitToUser(memberId, 'groupAdded', { groupId, name, addedByUserId: authedUserIdStr, role: 'member', at: nowIso });
      }

      // Also notify the creator 
      emitToUser(authedUserIdStr, 'groupAdded', { groupId, name, addedByUserId: authedUserIdStr, role: 'admin', at: nowIso });

      cb?.({
        success: true,
        group: {
          groupId,
          name,
          mlsEnabled: wantsMls,
          epoch: 0,
          cipherSuite: normalizedCipherSuite,
        },
        members: [
          { userId: authedUserIdStr, leafIndex: 0 },
          ...normalizedMemberIds.map((id, index) => ({ userId: id, leafIndex: index + 1 })),
        ],
      });
    } catch (err) {
      console.error('Error creating group:', err);
      if (groupId) {
        await Promise.allSettled([
          Group.deleteOne({ groupId }),
          GroupSequence.deleteOne({ groupId }),
          GroupMember.deleteMany({ groupId }),
        ]);
      }
      cb?.({ success: false, error: 'Error creating group' });
    }
  });

  const fetchGroupInfoForMember = async ({ groupId, authedUserId }) => {
    const groupIdStr = String(groupId ?? '');
    const authedUserIdStr = String(authedUserId ?? '');
    if (!groupIdStr) return { ok: false, error: 'Invalid groupId' };
    if (!authedUserIdStr) return { ok: false, error: 'unauthorized' };

    const [group, membership] = await Promise.all([
      Group.findOne({ groupId: groupIdStr }).lean(),
      GroupMember.findOne({ groupId: groupIdStr, userId: authedUserIdStr }).lean(),
    ]);

    if (!group) return { ok: false, error: 'Group not found' };
    if (!membership) return { ok: false, error: 'forbidden' };

    const members = await GroupMember.find({ groupId: groupIdStr }).lean();
    const memberIds = members.map((m) => String(m.userId));
    const profiles = await User.find({ id: { $in: memberIds } }, { id: 1, username: 1, profilePicture: 1 }).lean();
    const profileById = new Map(profiles.map((p) => [String(p.id), p]));

    return {
      ok: true,
      group: {
        groupId: group.groupId,
        name: group.name,
        createdBy: group.createdBy,
        createdAt: group.createdAt,
        mlsEnabled: group.mlsEnabled,
        epoch: group.epoch,
        cipherSuite: group.cipherSuite,
      },
      membership: {
        role: membership.role,
        joinedAt: membership.joinedAt,
        leafIndex: membership.leafIndex,
        status: membership.status,
      },
      members: members.map((m) => {
        const uid = String(m.userId);
        const p = profileById.get(uid);
        return {
          userId: uid,
          role: m.role,
          joinedAt: m.joinedAt,
          username: p?.username ?? null,
          profilePicture: p?.profilePicture ?? null,
          leafIndex: m.leafIndex,
          status: m.status,
        };
      }),
    };
  };

  // Back-compat: some clients emit "groupAdded" to fetch group metadata after receiving the notification.
  socket.on('groupAdded', async ({ groupId }, cb) => {
    const authedUserId = socket.user?.id;
    try {
      const res = await fetchGroupInfoForMember({ groupId, authedUserId });
      if (!res.ok) return cb?.({ success: false, error: res.error });
      return cb?.({ success: true, ...res });
    } catch (err) {
      console.error('Error fetching group info:', err);
      return cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('listMyGroups', async (_data, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const authedUserIdStr = String(authedUserId);
      const memberships = await GroupMember.find({ userId: authedUserIdStr }).lean();
      const groupIds = memberships.map((m) => String(m.groupId)).filter(Boolean);
      const groups = await Group.find({ groupId: { $in: groupIds } }).lean();
      const groupById = new Map(groups.map((g) => [String(g.groupId), g]));

      const result = memberships
        .map((m) => {
          const g = groupById.get(String(m.groupId));
          if (!g) return null;
          return {
            groupId: g.groupId,
            name: g.name,
            role: m.role,
            joinedAt: m.joinedAt,
            createdAt: g.createdAt,
            createdBy: g.createdBy,
            mlsEnabled: g.mlsEnabled,
            epoch: g.epoch,
            cipherSuite: g.cipherSuite,
            leafIndex: m.leafIndex,
            status: m.status,
          };
        })
        .filter(Boolean);

      cb?.({ success: true, groups: result });
    } catch (err) {
      console.error('Error listing groups:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('openGroup', async ({ groupId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr) return cb?.({ success: false, error: 'Invalid groupId' });

    try {
      const res = await fetchGroupInfoForMember({ groupId: groupIdStr, authedUserId });
      if (!res.ok) return cb?.({ success: false, error: res.error });

      const room = `group:${groupIdStr}`;
      socket.join(room);
      cb?.({ success: true, room, ...res });
    } catch (err) {
      console.error('Error opening group:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('fetchGroupMessages', async ({ groupId, beforeSeq, limit }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr) return cb?.({ success: false, error: 'Invalid groupId' });

    try {
      const membership = await GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean();
      if (!membership) return cb?.({ success: false, error: 'forbidden' });

      const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 200));
      const query = {
        conversationType: 'group',
        groupId: groupIdStr,
        $or: [
          { targetUserId: null },
          { targetUserId: String(authedUserId) },
        ],
      };
      const before = Number(beforeSeq);
      if (Number.isFinite(before)) query.seq = { $lt: before };

      const batchDesc = await Message.find(query).sort({ seq: -1 }).limit(safeLimit).lean();
      const batch = batchDesc.reverse();
      const nextBeforeSeq = batch.length > 0 ? batch[0].seq : null;

      cb?.({ success: true, messages: batch, nextBeforeSeq });
    } catch (err) {
      console.error('Error fetching group messages:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('addGroupMember', async ({ groupId, memberId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const memberIdStr = String(memberId ?? '');
    if (!groupIdStr || !memberIdStr) return cb?.({ success: false, error: 'Missing required fields' });

    try {
      const [group, callerMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
      ]);
      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership) return cb?.({ success: false, error: 'forbidden' });
      if (callerMembership.role !== 'admin') return cb?.({ success: false, error: 'forbidden' });

      const existing = await GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean();
      if (existing) return cb?.({ success: false, error: 'already_member' });

      // Determine the next leaf index for the new member
      const existingMembers = await GroupMember.find(
        { groupId: groupIdStr },
        { leafIndex: 1 }
      ).lean();

      const maxLeafIndex = existingMembers.reduce((max, member) => {
        return Number.isInteger(member.leafIndex) && member.leafIndex > max
          ? member.leafIndex
          : max;
      }, -1);

      const nextLeafIndex = maxLeafIndex + 1;

      // Este es diferente a los otros create group, tiene que fetch el numero de leafindex
      // Add the new member to the group
      await GroupMember.create({
        groupId: groupIdStr,
        userId: memberIdStr,
        role: 'member',
        joinedAt: new Date(),
        leafIndex: nextLeafIndex,
        status: 'active'
      });

      const nowIso = new Date().toISOString();
      const room = `group:${groupIdStr}`;

      const memberSocketId = userSocketMap[memberIdStr];
      if (memberSocketId) {
        io.to(memberSocketId).emit('groupAdded', {
          groupId: groupIdStr,
          name: group.name,
          addedByUserId: String(authedUserId),
          role: 'member',
          at: nowIso,
        });
      }

      io.to(room).emit('groupMemberAdded', {
        groupId: groupIdStr,
        memberId: memberIdStr,
        addedByUserId: String(authedUserId),
        role: 'member',
        at: nowIso,
      });

      cb?.({ success: true });
    } catch (err) {
      console.error('Error adding group member:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('removeGroupMember', async ({ groupId, memberId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const memberIdStr = String(memberId ?? '');
    if (!groupIdStr || !memberIdStr) return cb?.({ success: false, error: 'Missing required fields' });

    try {
      const [group, callerMembership, targetMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!targetMembership) return cb?.({ success: false, error: 'not_a_member' });

      const isSelf = String(authedUserId) === memberIdStr;
      const canRemove =
        isSelf ||
        (callerMembership.role === 'admin' && (targetMembership.role !== 'admin' || isSelf));
      if (!canRemove) return cb?.({ success: false, error: 'forbidden' });

      await GroupMember.deleteOne({ groupId: groupIdStr, userId: memberIdStr });

      const room = `group:${groupIdStr}`;
      const nowIso = new Date().toISOString();

      const memberSocketId = userSocketMap[memberIdStr];
      if (memberSocketId) {
        const memberSocket = io.sockets.sockets.get(memberSocketId);
        if (memberSocket) memberSocket.leave(room);
        io.to(memberSocketId).emit('groupRemoved', { groupId: groupIdStr, at: nowIso });
      }

      io.to(room).emit('groupMemberRemoved', {
        groupId: groupIdStr,
        memberId: memberIdStr,
        removedByUserId: String(authedUserId),
        at: nowIso,
      });

      cb?.({ success: true });
    } catch (err) {
      console.error('Error removing group member:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });


  socket.on('sendGroupMessage', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const ack = (payload) => {
      if (typeof callback === 'function') callback(payload);
    };

    const {
      groupId,
      payload,
      nonce,
      sendingNumber,
      previousSendingNumber,
      publicEphemeralKey,
      spkId,
      opkId,
      messageType,
      contentType,
      headerB64,
      ciphertextB64,
      epoch,
      senderLeafIndex,
    } = data ?? {};

    const groupIdStr = String(groupId ?? '');

    console.log('Saving group message:', { groupId: groupIdStr, authedUserId, hasPayload: Boolean(payload), hasNonce: Boolean(nonce) });

    try {
      // Fetch sender's profile information (and ensure the authenticated user exists).
      const [sender, group, membership] = await Promise.all([
        User.findOne({ id: authedUserId }),
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: authedUserId }).lean(),
      ]);
      if (!sender) {
        console.error('Sender not found:', authedUserId);
        ack({ success: false, error: 'Sender not found' });
        return;
      }

      if (!group) {
        ack({ success: false, error: 'Group not found' });
        return;
      }

      if (!membership) {
        ack({ success: false, error: 'Forbidden' });
        return;
      }

      if (!groupIdStr) {
        ack({ success: false, error: 'Missing required fields' });
        return;
      }

      const isMlsGroup = group.mlsEnabled === true;

      if (isMlsGroup) {
        const validContentTypes = new Set(['application', 'commit', 'welcome']);
        if (
          typeof contentType !== 'string' ||
          !validContentTypes.has(contentType) ||
          typeof headerB64 !== 'string' ||
          headerB64.length === 0 ||
          typeof ciphertextB64 !== 'string' ||
          ciphertextB64.length === 0 ||
          typeof epoch !== 'number' ||
          !Number.isInteger(senderLeafIndex)
        ) {
          ack({ success: false, error: 'Missing required fields' });
          return;
        }

        if (membership.leafIndex !== senderLeafIndex) {
          ack({ success: false, error: 'Forbidden' });
          return;
        }
      } else if (
        typeof payload !== 'string' ||
        payload.length === 0 ||
        typeof nonce !== 'string' ||
        nonce.length === 0
      ) {
        ack({ success: false, error: 'Missing required fields' });
        return;
      }

      await ensureGroupSequence(groupIdStr);

      // Server-assigned monotonic group sequence number.
      const updated = await GroupSequence.findOneAndUpdate(
        { groupId: groupIdStr },
        {
          $inc: { lastSequenceNumber: 1 },
          $set: { updatedAt: new Date() },
        },
        { new: true }
      );

      if (!updated) {
        ack({ success: false, error: 'Failed to allocate sequence number' });
        return;
      }

      const username = sender.username;
      const seq = updated.lastSequenceNumber;
      const message = new Message({
        payload: isMlsGroup ? null : payload,
        nonce,
        userId: authedUserId,
        targetUserId: null,
        conversationKey: null,
        username,
        seenStatus: false,
        messageNumber: null,
        sendingNumber,
        previousSendingNumber,
        publicEphemeralKey,
        spkId: spkId ?? null,
        opkId: opkId ?? null,
        messageType: typeof messageType === 'string' ? messageType : 'text',
        conversationType: 'group',
        groupId: groupIdStr,
        seq,
        epoch: isMlsGroup ? epoch : null,
        senderLeafIndex: isMlsGroup ? senderLeafIndex : null,
        contentType: isMlsGroup ? contentType : null,
        headerB64: isMlsGroup ? headerB64 : null,
        ciphertextB64: isMlsGroup ? ciphertextB64 : null,
      });

      await message.save();
      console.log('Message successfully saved:', message);

      const room = `group:${groupIdStr}`;

      // Enhanced message object with sender profile info
      const messageWithProfile = {
        ...message.toObject(),
        profileImage: sender.profilePicture || null,
        timestamp: message.createdAt,
        groupName: group?.name ?? null,
        epoch: message.epoch,
        senderLeafIndex: message.senderLeafIndex,
        contentType: message.contentType,
        headerB64: message.headerB64,
        ciphertextB64: message.ciphertextB64,
      };

      // Emit to the group room (for users who have the group open)
      io.to(room).emit('newGroupMessage', messageWithProfile);

      // Also notify online group members directly if they are not in the room.
      const members = await GroupMember.find({ groupId: groupIdStr }, { userId: 1 }).lean();
      for (const m of members) {
        const memberId = String(m?.userId ?? '');
        const memberSocketId = userSocketMap[memberId];
        if (!memberSocketId) continue;

        const memberSocket = io.sockets.sockets.get(memberSocketId);
        if (!memberSocket || !memberSocket.rooms?.has(room)) {
          io.to(memberSocketId).emit('newGroupMessage', messageWithProfile);
        }
      }

      ack({ success: true, seq });
    } catch (err) {
      console.error('Error saving group message:', err);
      const details =
        process.env.NODE_ENV && process.env.NODE_ENV.toLowerCase() === 'production'
          ? undefined
          : (err?.message ?? String(err));
      ack({ success: false, error: 'Error saving message', details });
    }
  });

  socket.on('sendGroupWelcome', async ({ groupId, recipientUserId, welcome }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const recipientUserIdStr = String(recipientUserId ?? '');
    const senderUserIdStr = String(authedUserId);

    if (!welcome || typeof welcome !== 'object' || !recipientUserIdStr || !groupIdStr) {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, senderMembership, recipientMembership, sender] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: senderUserIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: recipientUserIdStr }).lean(),
        User.findOne({ id: senderUserIdStr }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!recipientMembership) return cb?.({ success: false, error: 'Recipient is not a member of the group' });
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(welcome.groupId ?? '') !== groupIdStr) {
        return cb?.({ success: false, error: 'Welcome groupId mismatch' });
      }
      if (String(welcome.recipientUserId ?? '') !== recipientUserIdStr) {
        return cb?.({ success: false, error: 'Welcome recipient mismatch' });
      }

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: senderUserIdStr,
        senderUsername: sender.username,
        targetUserId: recipientUserIdStr,
        epoch: welcome.epoch,
        senderLeafIndex: senderMembership.leafIndex,
        contentType: 'welcome',
        artifact: welcome,
      });

      const recipientSocketId = userSocketMap[recipientUserIdStr];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('groupWelcome', {
          groupId: groupIdStr,
          welcome
        });
      }
      return cb?.({ success: true, delivered: Boolean(recipientSocketId) });

    } catch (err) {
      console.error('Error sending group welcome:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('fetchPendingWelcomes', async (_, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    try {
      const stored = await Message.find({
        conversationType: 'group',
        contentType: 'welcome',
        targetUserId: String(authedUserId),
      }).lean();

      const welcomes = stored
        .map((msg) => {
          try {
            const welcome = JSON.parse(msg.payload);
            return { groupId: msg.groupId, welcome };
          } catch {
            return null;
          }
        })
        .filter(Boolean);

      cb?.({ success: true, welcomes });
    } catch (err) {
      console.error('Error fetching pending welcomes:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('sendGroupCommit', async ({ groupId, commit }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr || !commit || typeof commit !== 'object') {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, senderMembership, sender] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
        User.findOne({ id: String(authedUserId) }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(commit.groupId ?? '') !== groupIdStr) {
        return cb?.({ success: false, error: 'Commit groupId mismatch' });
      }
      if (
        Number.isInteger(commit.senderLeafIndex) &&
        Number.isInteger(senderMembership.leafIndex) &&
        commit.senderLeafIndex !== senderMembership.leafIndex
      ) {
        return cb?.({ success: false, error: 'Forbidden' });
      }

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: String(authedUserId),
        senderUsername: sender.username,
        epoch: commit.epoch,
        senderLeafIndex: commit.senderLeafIndex,
        contentType: 'commit',
        artifact: commit,
      });

      if (Number.isInteger(commit.epoch)) {
        await Group.updateOne(
          { groupId: groupIdStr },
          { $max: { epoch: commit.epoch }, $set: { updatedAt: new Date() } }
        );
      }

      const delivered = await emitEventToGroupMembers({
        groupId: groupIdStr,
        eventName: 'groupCommit',
        payload: { groupId: groupIdStr, commit },
      });

      return cb?.({ success: true, delivered });
    } catch (err) {
      console.error('Error sending group commit:', err);
      return cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('publishKeyPackage', async ({ initKeyB64 }, cb) => {
    const userId = String(socket.user?.id ?? '');
    const normalizedInitKeyB64 = typeof initKeyB64 === 'string' ? initKeyB64.trim() : '';

    if (!userId) return cb?.({ success: false, error: 'unauthorized' });
    if (!normalizedInitKeyB64)
      return cb?.({ success: false, error: 'Missing initKeyB64' });

    try {
      await KeyPackage.findOneAndUpdate(
        { userId },
        {
          $set: {
            userId,
            initKeyB64: normalizedInitKeyB64,
            updatedAt: new Date(),
          },
        },
        {
          upsert: true,
          new: true,
          runValidators: true,
          setDefaultsOnInsert: true,
        }
      );
      cb?.({ success: true });
    } catch (err) {
      console.error('publishKeyPackage error:', {
        userId,
        initKeyLength: normalizedInitKeyB64.length,
        message: err?.message,
        code: err?.code,
        stack: err?.stack,
      });
      cb?.({ success: false, error: err?.message || 'Internal server error' });
    }
  })

  socket.on('fetchKeyPackage', async ({ userId: targetId }, cb) => {
    const callerId = socket.user?.id;
    if (!callerId) return cb?.({ success: false, error: 'unauthorized' });

    try {
      const kp = await KeyPackage.findOne({ userId: String(targetId ?? '') }).lean();
      if (!kp) return cb?.({ success: false, error: 'KeyPackage not found' });
      cb?.({ success: true, initKeyB64: kp.initKeyB64 });
    } catch (err) {
      console.error('fetchKeyPackage error:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('initiateCall', async ({ targetUserId, callId }) => {
    const callerId = socket.user?.id;
    const callerName = socket.user?.username;

    if (!callerId || !targetUserId || !callId) return;

    console.log('Received initiateCall:', { targetUserId, callId, callerId });
    const targetSocketId = userSocketMap[targetUserId];
    const targetUserIdString = String(targetUserId);

    if (targetSocketId) {
      io.to(targetSocketId).emit('incomingCall', { callId, callerId, callerName });
      console.log(`Call notification sent to ${targetUserId} (socket: ${targetSocketId})`);

      const call = new Call({
        callId,
        callerId,
        receiverId: targetUserIdString,
        status: 'ringing',
        startedAt: new Date(),
        endedAt: null,
        callType: 'video',
        duration: 0,
      });
      await call.save();

      setTimeout(async () => {
        const currentCall = await Call.findOne({ callId });
        if (currentCall && currentCall.status === 'ringing') {
          currentCall.status = 'missed';
          currentCall.endedAt = new Date();
          await currentCall.save();

          await createCallEventMessage({
            callId,
            status: 'missed',
            duration: 0
          });

          console.log('Call marked as missed:', callId);
        }
        // 30 Seconds
      }, 30000);

    } else {
      console.log(`User ${targetUserId} is not online`);
    }
  });

  socket.on('acceptCall', async ({ callId }) => {
    try {
      const call = await Call.findOneAndUpdate(
        { callId },
        { $set: { status: 'in-progress' } },
        { new: true }
      );

      if (!call) {
        console.log('Call not found for acceptCall:', callId);
        return;
      }

      // Notify caller that call was accepted (optional)
      const callerSocketId = userSocketMap[call.callerId];
      if (callerSocketId) {
        io.to(callerSocketId).emit('callAccepted', { callId });
      }

      console.log('Call marked as in-progress:', callId);
    } catch (err) {
      console.error('Error in acceptCall:', err);
    }
  });

  socket.on('declineCall', async ({ callId }) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !callId) return;

    try {
      const call = await Call.findOne({ callId });
      if (!call) {
        console.log('Call not found for declineCall:', callId);
        return;
      }
      if (authedUserId !== call.receiverId && authedUserId !== call.callerId) {
        console.log('Unauthorized declineCall attempt:', { callId, authedUserId });
        return;
      }

      const callerSocketId = userSocketMap[call.callerId];
      if (callerSocketId) {
        io.to(callerSocketId).emit('callDeclined', { callId });
      }

      await Call.findOneAndUpdate(
        { callId },
        {
          $set: {
            status: 'declined',
            endedAt: new Date(),
            duration: 0,
          },
        }
      );
      console.log('Call marked as declined:', callId);

      // Create call event message for declined call
      await createCallEventMessage({
        callId,
        status: 'declined',
        duration: 0
      });

    } catch (err) {
      console.error('Error updating declined call:', err);
    }
  });

  socket.on('endCall', async ({ callId }) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !callId) return;

    try {
      const call = await Call.findOne({ callId });

      if (!call) {
        console.log('Call not found for endCall:', callId);
        return;
      }

      if (authedUserId !== call.receiverId && authedUserId !== call.callerId) {
        console.log('Unauthorized endCall attempt:', { callId, authedUserId });
        return;
      }

      const otherUserId = authedUserId === call.callerId ? call.receiverId : call.callerId;
      const targetSocketId = userSocketMap[otherUserId];
      if (targetSocketId) {
        io.to(targetSocketId).emit('callEnded', { callId });
      }

      const endedAt = new Date();
      const durationSeconds = Math.max(
        0,
        Math.round((endedAt - call.startedAt) / 1000)
      );

      call.status = 'ended';
      call.endedAt = endedAt;
      call.duration = durationSeconds;

      await call.save();

      console.log('Call ended and updated:', {
        callId,
        durationSeconds,
      });

      // Create call event message in chat
      await createCallEventMessage({
        callId,
        status: 'ended',
        duration: durationSeconds
      });

    } catch (err) {
      console.error('Error ending call:', err);
    }
  });

  // Handle video state changes during call
  socket.on('videoStateChanged', ({ targetUserId, isEnabled }) => {
    const targetSocketId = userSocketMap[targetUserId];
    if (targetSocketId) {
      io.to(targetSocketId).emit('videoStateChanged', { isEnabled });
      console.log(`Video state changed for ${targetUserId}: ${isEnabled ? 'enabled' : 'disabled'}`);
    }
  });

  // Handle audio state changes during call
  socket.on('audioStateChanged', ({ targetUserId, isEnabled }) => {
    const targetSocketId = userSocketMap[targetUserId];
    if (targetSocketId) {
      io.to(targetSocketId).emit('audioStateChanged', { isEnabled });
      console.log(`Audio state changed for ${targetUserId}: ${isEnabled ? 'enabled' : 'disabled'}`);
    }
  });

  // Live captions (client-side speech-to-text; server relays text only)
  socket.on('captionInterim', ({ targetUserId, callId, text }) => {
    if (typeof text !== 'string' || text.trim().length === 0) return;
    const fromUserId = socket.user?.id;
    const fromUsername = socket.user?.username;
    if (!fromUserId) return;
    const targetSocketId = userSocketMap[targetUserId];
    if (targetSocketId) {
      io.to(targetSocketId).emit('captionInterim', {
        callId,
        text: text.trim(),
        fromUserId,
        fromUsername,
      });
    }
  });

  socket.on('captionFinal', ({ targetUserId, callId, text }) => {
    if (typeof text !== 'string' || text.trim().length === 0) return;
    const fromUserId = socket.user?.id;
    const fromUsername = socket.user?.username;
    if (!fromUserId) return;
    const targetSocketId = userSocketMap[targetUserId];
    if (targetSocketId) {
      io.to(targetSocketId).emit('captionFinal', {
        callId,
        text: text.trim(),
        fromUserId,
        fromUsername,
      });
    }
  });

  socket.on('searchUser', async (data, callback) => {
    const username = data.searchTerm;
    console.log("Data:", data);
    console.log('Search user:', username);

    try {
      const user = await User.findOne({ username });
      if (!user) {
        console.log('User not found');
        return callback({ success: false, error: 'User not found' });
      }
      console.log('Found user:', user);
      callback({ success: true, user: { id: user.id, username: user.username } });
    } catch (error) {
      console.error('Error searching user:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('updateUserInfo', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' })

    console.log('========== [updateUserInfo] ==========');
    console.log('Received data:', JSON.stringify(data, null, 2));
    const { username, aboutme, profilePicture, oldPassword, newPassword } = data;
    try {
      const user = await User.findOne({ id: authedUserId });
      if (!user) {
        return callback && callback({ success: false, error: 'User not found' });
      }

      if (typeof username === 'string' && username.length > 0) {
        user.username = username;
      }

      if (typeof aboutme === 'string') {
        user.aboutme = aboutme;
      }

      if (typeof profilePicture === 'string' && profilePicture.startsWith('data:image/')) {
        const url = await saveProfilePicture(profilePicture, authedUserId);
        user.profilePicture = url;
      }

      if (oldPassword && newPassword) {
        const isMatch = await bcrypt.compare(oldPassword, user.hashedPassword);
        if (!isMatch) {
          return callback && callback({ success: false, error: 'Old password is incorrect' });
        }
        user.hashedPassword = await bcrypt.hash(newPassword, 10);
      }

      await user.save();
      callback && callback({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          aboutme: user.aboutme,
          profilePicture: user.profilePicture,
        }
      });
    } catch (err) {
      // Handle duplicate username error
      if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
        return callback && callback({ success: false, error: "Username already taken" });
      }
      console.error('Error updating user info:', err);
      callback && callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getUserInfo', async ({ userId }, cb) => {
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        console.log('User found:', user);
        cb({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            aboutme: user.aboutme,
            profilePicture: user.profilePicture,
            friends: user.friends
          }
        });
      } else {
        cb({ success: false, error: 'User not found' });
      }
    } catch (err) {
      console.error('Error fetching user info:', err);
      cb({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('deleteAccount', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' })

    console.log("Received deleteAccount for userId:", authedUserId);
    try {
      const userResult = await User.deleteOne({ id: authedUserId });
      const msgResult = await Message.deleteMany({
        $or: [{ userId: authedUserId }, { targetUserId: authedUserId }],
      });
      console.log("User delete result:", userResult);
      console.log("Message delete result:", msgResult);
      callback && callback({ success: true });
    } catch (err) {
      console.error('Error deleting account:', err);
      callback && callback({ success: false, error: 'Failed to delete account' });
    }
  });

  // Add this to your existing socket.io server code
  socket.on('addFriend', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const { targetUserId } = data;
    console.log(`Adding friend: ${authedUserId} wants to add ${targetUserId}`);

    try {
      // Check if both users exist
      const [user, targetUser] = await Promise.all([
        User.findOne({ id: authedUserId }),
        User.findOne({ id: targetUserId })
      ]);

      if (!user || !targetUser) {
        console.log('One or both users not found');
        return callback({ success: false, error: 'User(s) not found' });
      }

      // Check if already friends
      if (user.friends.includes(targetUserId)) {
        console.log('Users are already friends');
        return callback({ success: false, error: 'Already friends' });
      }

      // Add targetUserId to user's friends array
      user.friends.push(targetUserId);
      await user.save();

      console.log(`Successfully added ${targetUserId} to ${authedUserId}'s friends list`);

      // Notify both users about the new friendship
      const userSocketId = userSocketMap[authedUserId];
      const targetSocketId = userSocketMap[targetUserId];

      if (userSocketId) {
        io.to(userSocketId).emit('friendAdded', {
          friendId: targetUserId,
          friendUsername: targetUser.username
        });
      }

      if (targetSocketId) {
        io.to(targetSocketId).emit('friendAdded', {
          friendId: authedUserId,
          friendUsername: user.username
        });
      }

      callback({ success: true });
    } catch (err) {
      console.error('Error adding friend:', err);
      callback({ success: false, error: 'Failed to add friend' });
    }
  });
  // Add this to your existing socket.io server code
  socket.on('removeFriend', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const { targetUserId } = data;
    console.log(`Removing friend: ${authedUserId} wants to remove ${targetUserId}`);

    try {
      // Check if both users exist
      const [user, targetUser] = await Promise.all([
        User.findOne({ id: authedUserId }),
        User.findOne({ id: targetUserId })
      ]);

      if (!user || !targetUser) {
        console.log('One or both users not found');
        return callback({ success: false, error: 'User(s) not found' });
      }

      // Check if they are actually friends
      const userFriendIndex = user.friends.indexOf(targetUserId);
      const targetFriendIndex = targetUser.friends.indexOf(authedUserId);

      if (userFriendIndex === -1 || targetFriendIndex === -1) {
        console.log('Users are not friends');
        return callback({ success: false, error: 'Not friends' });
      }

      // Remove from both users' friend lists
      user.friends.splice(userFriendIndex, 1);
      targetUser.friends.splice(targetFriendIndex, 1);

      await Promise.all([user.save(), targetUser.save()]);

      console.log(`Successfully removed friendship between ${authedUserId} and ${targetUserId}`);

      // Notify both users about the removed friendship
      const userSocketId = userSocketMap[authedUserId];
      const targetSocketId = userSocketMap[targetUserId];

      if (userSocketId) {
        io.to(userSocketId).emit('friendRemoved', {
          friendId: targetUserId
        });
      }

      if (targetSocketId) {
        io.to(targetSocketId).emit('friendRemoved', {
          friendId: authedUserId
        });
      }

      callback({ success: true });
    } catch (err) {
      console.error('Error removing friend:', err);
      callback({ success: false, error: 'Failed to remove friend' });
    }
  });
});



if (require.main === module) {
  server.listen(3001, () => {
    console.log('listening on *:3001');
  });
}

module.exports = {
  app,
  server,
  io,
  mongoose,
  Message,
  User,
  Call,
  OpkRequestLog,
  MessageSequence,
};

