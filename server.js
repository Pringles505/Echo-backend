const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');

const shortid = require('shortid');

require('dotenv').config(); 

const app = express();
const server = http.createServer(app);

const io = require('socket.io')(server, {
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
  id: {type: String, unique: true},
  username: String,
  hashedPassword: String,
});

const messageSchema = new mongoose.Schema({
  text: String,
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
    const {username, password} = data;
    console.log('Received register:', data);
    // All upper case, number, and letter, 7 characters
    // 36^7 = 78,364,164,096 combinations * more with special characters
    const id = shortid.generate().toUpperCase().slice(0, 7);
    hashedPassword = bcrypt.hashSync(password, 10);
    const user = new User({ id, username, hashedPassword });
    user.save().then(() => {
      console.log('User saved:', user);
      callback({ success: true });
    }).catch((err) => {
      console.error('Error saving user:', err);
      callback({ success: false });
    });

  })

  socket.on('login', async (data, callback) => {
  const { username, password } = data;
  console.log('Login event received:', { username, password });

  try {
    // Query the database for the user
    const user = await User.findOne({ username });
    if (!user) {
      console.log('User not found');
      return callback({ success: false, error: 'Invalid username or password' });
    }

    console.log('Found user:', user);
    // Compare passwords
    console.log('before check password', password, user.hashedPassword);
    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
      console.log('Password mismatch');
      console.log('Password:', password, 'Hashed Password:', user.password);
      return callback({ success: false, error: 'Invalid username or password' });
    }
    console.log('Password match');

    // Generate a JWT
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


  socket.on('chat message', (msg) => {
    console.log('Received chat message:', msg);
    const message = new Message({ text: msg });
    message.save().then(() => {
      console.log('Message saved:', message); 
      io.emit('chat message', message);
    }).catch((err) => {
      console.error('Error saving message:', err);
    });
  });
  
});

server.listen(3001, () => {
  console.log('listening on *:3001');
});