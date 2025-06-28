const express = require('express');
require('dotenv').config();
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { customAlphabet } = require('nanoid');
const path = require('path');
const fs = require('fs');

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

const userSocketMap = {};

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

app.use(cors({
  origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
  aboutme: { type: String, default: '' },
  profilePicture: { type: String, default: '' },
});

const messageSchema = new mongoose.Schema({
  is_initial: Boolean,
  text: String,
  userId: String,
  targetUserId: String,
  username: String,
  messageNumber: Number,
  publicEphemeralKey: String,
  seenStatus: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);
const User = mongoose.model('User', userSchema);

const authenticate = (socket, next) => {
  const token = socket.handshake.auth.token;
  console.log("Received Token:", token);

  if (!token) {
    console.warn('No token provided, allowing unauthenticated access for login/register');
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (!err && decoded) {
      userSocketMap[decoded.id] = socket.id;
      console.log(`User ${decoded.username} is mapped to socket ${socket.id}`);
    }
    if (err) {
      console.error('Invalid token:', err);
      return next(new Error('Authentication error'));
    }
    socket.user = decoded;
    next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {
  console.log(`A user connected with socket ID: ${socket.id}`);

  const token = socket.handshake.auth.token;

  if (token) {
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (!err && decoded) {
      userSocketMap[decoded.id] = socket.id;

      // Notify other clients that user is online
      socket.broadcast.emit('userOnline', { userId: decoded.id });

      console.log(`User ${decoded.username} (ID: ${decoded.id}) mapped to socket ${socket.id}`);
    }
  });
}


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

  socket.on('ready', async ({ userId, targetUserId }) => {
    console.log(`User ${userId} is opening chat with ${targetUserId}`);

    // Create a private room between userId and targetUserId
    const room = [userId, targetUserId].sort().join('_');
    socket.join(room);

    try {
      const message = await Message.find({
        $or: [
          { userId, targetUserId },
          { userId: targetUserId, targetUserId: userId },
        ],
      }).sort({ createdAt: 1 });

      console.log(`Sending ${message.length} messages to User ${userId} ↔ ${targetUserId}`);

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
      callback({ success: true, signedPreKey: user.signedPreKey, signature: user.signature });
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
    const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey } = keyBundle;
    const [signedPreKey, signature] = publicSignedPreKey;

    console.log('Received register:', data);
    console.log('Public Identity Key X25519:', publicIdentityKeyX25519);
    console.log('Public Identity Key Ed25519:', publicIdentityKeyEd25519);

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
      const id = nanoid();
      const user = new User({
        id,
        username,
        hashedPassword,
        publicIdentityKeyX25519,
        publicIdentityKeyEd25519,
        signedPreKey,
        signature,
        aboutme: typeof aboutme === 'string' ? aboutme : '',
        profilePicture: typeof profilePicture === 'string' ? profilePicture : '',
      });

      await user.save();
      console.log('User saved:', user);
      callback({ success: true });
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
    const { userId, targetUserId } = data;
    console.log("Message from ", userId, " seen by ", targetUserId);

    try {
      // Log the query and update
      console.log('Updating messages with query:', { userId, targetUserId, seenStatus: false });
      console.log('Update operation:', { $set: { seenStatus: true } });

      const result = await Message.updateMany(
        { userId: targetUserId, targetUserId: userId, seenStatus: false },
        { $set: { seenStatus: true } }
      );

      console.log('Updated messages seenStatus:', result);

      const senderSocketId = userSocketMap[targetUserId];
      if (senderSocketId) {
        io.to(senderSocketId).emit('messageSeenUpdate', { userId, targetUserId });
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
        { expiresIn: '1h' }
      );
      console.log('Generated Token:', token);

      callback({ success: true, token });
    } catch (err) {
      console.error('Error during login:', err);
      callback({ success: false, error: 'Login failed' });
    }
  });

  socket.on('checkIfMessagesExist', async (data, callback) => {
    const { userId, targetUserId } = data;
    console.log('Checking if messages exist for:', { userId, targetUserId });

    try {
      const message_1 = await Message.findOne({ userId, targetUserId });
      const message_2 = await Message.findOne({ userId: targetUserId, targetUserId: userId });
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
    const { userId, targetUserId } = data;

    try {
      // Search for messages in either direction
      const latestMessage = await Message.findOne({
        $or: [
          { userId, targetUserId },
          { userId: targetUserId, targetUserId: userId }
        ]
      }).sort({ messageNumber: -1 });

      // Return the found message number or 0 if none exist
      callback({
        success: true,
        messageNumber: latestMessage?.messageNumber ?? 0
      });
    } catch (err) {
      console.error('Error:', err);
      callback({
        success: false,
        messageNumber: 0  // Fallback value
      });
    }
  });


  socket.on('newMessage', async (data) => {
    const { is_initial, text, userId, targetUserId, username, messageNumber, publicEphemeralKey } = data;

    if (!text || !userId || !targetUserId || !username) {
      console.error('Missing fields in message data:', { text, userId, targetUserId, username, messageNumber, is_initial });
      return;
    }

    console.log('Saving message:', { text, userId, targetUserId, username, messageNumber, is_initial, publicEphemeralKey });

    try {
      const message = new Message({
        is_initial,
        text,
        userId,
        targetUserId,
        username,
        seenStatus: false,
        messageNumber,
        publicEphemeralKey,
      });

      await message.save();
      console.log('Message successfully saved:', message);

      // Create consistent room name
      const room = [userId, targetUserId].sort().join('_');

      // Emit only to that room (both users)
      io.to(room).emit('newMessage', message);

      // Optionally, emit a separate 'notification' event to the other user
      const targetSocketId = userSocketMap[targetUserId];
      if (targetSocketId) {
        io.to(targetSocketId).emit('notification', {
          messageData: message,
        });
      }

    } catch (err) {
      console.error('Error saving message:', err);
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
    console.log('========== [updateUserInfo] ==========');
    console.log('Received data:', JSON.stringify(data, null, 2));
    const { userId, username, aboutme, profilePicture, oldPassword, newPassword } = data;
    try {
      const user = await User.findOne({ id: userId });
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
        const url = await saveProfilePicture(profilePicture, userId);
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
    const { userId } = data;
    console.log("Received deleteAccount for userId:", userId);
    try {
      const userResult = await User.deleteOne({ id: userId });
      const msgResult = await Message.deleteMany({ $or: [{ userId }, { targetUserId: userId }] });
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
  const { userId, targetUserId } = data;
  console.log(`Adding friend: ${userId} wants to add ${targetUserId}`);

  try {
    // Check if both users exist
    const [user, targetUser] = await Promise.all([
      User.findOne({ id: userId }),
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

    console.log(`Successfully added ${targetUserId} to ${userId}'s friends list`);

    // Notify both users about the new friendship
    const userSocketId = userSocketMap[userId];
    const targetSocketId = userSocketMap[targetUserId];

    if (userSocketId) {
      io.to(userSocketId).emit('friendAdded', {
        friendId: targetUserId,
        friendUsername: targetUser.username
      });
    }

    if (targetSocketId) {
      io.to(targetSocketId).emit('friendAdded', {
        friendId: userId,
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
  const { userId, targetUserId } = data;
  console.log(`Removing friend: ${userId} wants to remove ${targetUserId}`);

  try {
    // Check if both users exist
    const [user, targetUser] = await Promise.all([
      User.findOne({ id: userId }),
      User.findOne({ id: targetUserId })
    ]);

    if (!user || !targetUser) {
      console.log('One or both users not found');
      return callback({ success: false, error: 'User(s) not found' });
    }

    // Check if they are actually friends
    const userFriendIndex = user.friends.indexOf(targetUserId);
    const targetFriendIndex = targetUser.friends.indexOf(userId);

    if (userFriendIndex === -1 || targetFriendIndex === -1) {
      console.log('Users are not friends');
      return callback({ success: false, error: 'Not friends' });
    }

    // Remove from both users' friend lists
    user.friends.splice(userFriendIndex, 1);
    targetUser.friends.splice(targetFriendIndex, 1);

    await Promise.all([user.save(), targetUser.save()]);

    console.log(`Successfully removed friendship between ${userId} and ${targetUserId}`);

    // Notify both users about the removed friendship
    const userSocketId = userSocketMap[userId];
    const targetSocketId = userSocketMap[targetUserId];

    if (userSocketId) {
      io.to(userSocketId).emit('friendRemoved', {
        friendId: targetUserId
      });
    }

    if (targetSocketId) {
      io.to(targetSocketId).emit('friendRemoved', {
        friendId: userId
      });
    }

    callback({ success: true });
  } catch (err) {
    console.error('Error removing friend:', err);
    callback({ success: false, error: 'Failed to remove friend' });
  }
});
});



server.listen(3001, () => {
  console.log('listening on *:3001');
});

