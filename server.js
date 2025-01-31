const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { customAlphabet } = require('nanoid');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
    methods: ['GET', 'POST'],
  },
});

app.use(cors({
  origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
}));
app.use(express.json());

const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('Error connecting to MongoDB', err);
});

const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  username: String,
  hashedPassword: String,
  friends: [String],
});

const messageSchema = new mongoose.Schema({
  text: String,
  userId: String,
  targetUserId: String, 
  username: String,
  createdAt: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);
const User = mongoose.model('User', userSchema);

const authenticate = (socket, next) => {
  const token = socket.handshake.auth.token;

  if (!token) {
    console.warn('No token provided, allowing unauthenticated access for login/register');
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
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
  console.log('a user connected');

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
        const messages = await Message.find({
            $or: [
                  { userId, targetUserId },
                  { userId: targetUserId, targetUserId: userId },
            ],
        }).sort({ createdAt: 1 }); 

        console.log(`Sending ${messages.length} messages to User ${userId} ↔ ${targetUserId}`);

        // Message is emitted to users in room and no one else
        io.to(room).emit('init', messages);
    } catch (err) {
        console.error('Error fetching messages:', err);
    }
});



  socket.on('disconnect', () => {
    console.log('user disconnected');
  });

  socket.on('register', async (data, callback) => {
    const { username, password } = data;
    console.log('Received register:', data);

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
      const id = nanoid();
      const user = new User({ id, username, password: hashedPassword });
      await user.save();
      console.log('User saved:', user);
      callback({ success: true });
    } catch (err) {
      console.error('Error saving user:', err);
      callback({ success: false });
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

  socket.on('chat message', async (data) => {
    console.log('Received Data:', data);

    const { text, userId, targetUserId, username } = data;

    if (!text || !userId || !targetUserId || !username) {
      console.error('Missing fields in message data:', { text, userId, targetUserId, username });
      return;
    }

    console.log('Saving message:', { text, userId, targetUserId, username });

    try {
      const message = new Message({ text, userId, targetUserId, username });
      await message.save();
      console.log('Message successfully saved:', message);
      socket.broadcast.emit('chat message', message);

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
      console.error('Error searching for user:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });
});

server.listen(3001, () => {
  console.log('listening on *:3001');
});