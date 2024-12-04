const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const shortid = require('shortid');

require('dotenv').config(); 

const app = express();
const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
    methods: ['GET', 'POST'],
  },
  transports: ['polling', 'websocket'],
});

// Use this CORS configuration to allow your frontend domain
app.use(cors({
  origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'], 
  methods: ['GET', 'POST'], 
  allowedHeaders: ['Content-Type'], 
  credentials: true, 
}));

const mongoUri = process.env.MONGO_URI;

mongoose.connect(mongoUri).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('Error connecting to MongoDB', err);
});

// Database Schemas
const userSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  username: String,
  hashedPassword: String,
});

const messageSchema = new mongoose.Schema({
  text: String,
  user1: String,
  user2: String,
  conversationId: String,
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

  // Verify the token
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

  Message.find().then((messages) => {
    console.log('Sending init messages:', messages);
    socket.emit('init', messages);
  }).catch((err) => {
    console.error('Error fetching messages:', err);
  });

  socket.on('disconnect', () => {
    console.log('user disconnected');
  });

  socket.on('register', (data, callback) => {
    const { username, password } = data;
    console.log('Received register:', data);
    const id = shortid.generate().toUpperCase().slice(0, 7);
    const hashedPassword = bcrypt.hashSync(password, 10); 
    const user = new User({ id, username, hashedPassword });
    user.save().then(() => {
      console.log('User saved:', user);
      callback({ success: true });
    }).catch((err) => {
      console.error('Error saving user:', err);
      callback({ success: false });
    });
  });

  socket.on('login', async (data, callback) => {
    const { username, password } = data;
    console.log('Login event received:', { username, password });

    try {
      const user = await User.findOne({ username });
      if (!user) {
        console.log('User not found');
        return callback({ success: false, error: 'Invalid username or password' });
      }

      console.log('Found user:', user);
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

  socket.on('chat message', (data) => {
    console.log('Received Data:', data);
    const { text, userId } = data;
    console.log('Received message:', text);
    console.log('User ID:', userId);
    const message = new Message({ text, user: userId });
    message.save().then(() => {
      io.emit('chat message', message);
    }).catch((err) => {
      console.error('Error saving message:', err);
    });
  });

  socket.on('startChat', async (data, callback) => {
    console.log('Data:', data);
    const { userId, targetUserId } = data;
    console.log('Start chat:', userId, targetUserId);
  
    const sortedIds = [userId, targetUserId].sort();
    const conversationId = `${sortedIds[0]}${sortedIds[1]}`;
    const text = "INITIATE CONVERSATION"; 
    const message = new Message({ text, user1: userId, user2: targetUserId, conversationId });
  
    try {
      await message.save();
      console.log('Message saved:', message);
      io.emit('chat message', message);
  
      // Check if callback is a function before calling it
      if (typeof callback === 'function') {
        callback({ success: true, message });
      } else {
        console.error('Callback is not a function');
      }
    } catch (err) {
      console.error('Error saving message:', err);
      if (typeof callback === 'function') {
        callback({ success: false, error: 'Failed to start chat' });
      }
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
