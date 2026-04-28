/**
 * Registers and returns all mongoose models used by the app.
 * This keeps persistence details out of the runtime bootstrap.
 */
function createModels(mongoose) {
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
      default: 'text',
    },
    callData: {
      status: {
        type: String,
        enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed'],
      },
      callType: String,
      duration: Number,
      callerId: String,
      receiverId: String,
      callId: String,
    },
    conversationType: {
      type: String,
      enum: ['direct', 'group'],
      default: 'direct',
    },
    groupId: { type: String, default: null, index: true },
    seq: { type: Number, default: null, index: true, groupId: 1, seq: 1 },
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
    outcome: String,
    retryAfterMs: { type: Number, default: 0 },
    opkConsumed: { type: Boolean, default: false },
    opkId: { type: String, default: null },
    createdAt: { type: Date, default: Date.now, index: true },
  });
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

  const keyPackageSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    initKeyB64: { type: String, required: true },
    updatedAt: { type: Date, default: Date.now },
  });

  const Message = mongoose.models.Message || mongoose.model('Message', messageSchema);
  const User = mongoose.models.User || mongoose.model('User', userSchema);
  const MessageSequence =
    mongoose.models.MessageSequence || mongoose.model('MessageSequence', messageSequenceSchema);
  const OpkRequestLog =
    mongoose.models.OpkRequestLog || mongoose.model('OpkRequestLog', opkRequestLogSchema);
  const Call = mongoose.models.Call || mongoose.model('Call', calls);
  const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);
  const GroupMember = mongoose.models.GroupMember || mongoose.model('GroupMember', groupMemberSchema);
  const GroupSequence =
    mongoose.models.GroupSequence || mongoose.model('GroupSequence', groupSequenceSchema);
  const KeyPackage = mongoose.models.KeyPackage || mongoose.model('KeyPackage', keyPackageSchema);

  return {
    Message,
    User,
    MessageSequence,
    OpkRequestLog,
    Call,
    Group,
    GroupMember,
    GroupSequence,
    KeyPackage,
  };
}

async function syncKeyPackageIndexes(KeyPackage) {
  try {
    const droppedIndexes = await KeyPackage.syncIndexes();
    console.log('[MLS] KeyPackage indexes synced', droppedIndexes);
  } catch (err) {
    console.error('[MLS] Failed to sync KeyPackage indexes:', err);
  }
}

module.exports = {
  createModels,
  syncKeyPackageIndexes,
};
