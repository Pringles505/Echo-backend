const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');

const shortid = require('shortid');

require('dotenv').config(); 

const app = express();
const server = http.createServer(app);

const io = require('socket.io')(server, {
  cors: {
    origin: ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'],
    methods: ['GET', 'POST'],
  },
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
    const {username, hashedPassword} = data;
    console.log('Received register:', data);
    // All upper case, number, and letter, 7 characters
    // 36^7 = 78,364,164,096 combinations * more with special characters
    const id = shortid.generate().toUpperCase().slice(0, 7);
    
    const user = new User({ id, username, hashedPassword });
    user.save().then(() => {
      console.log('User saved:', user);
      callback({ success: true });
    }).catch((err) => {
      console.error('Error saving user:', err);
      callback({ success: false });
    });

  })

  socket.on('login', (data, callback) => {
    const { username, hashedPassword } = data;
    console.log('Received login:', data);
    User.findOne({ username, hashedPassword }).then((user) => {
      console.log('User found:', user);
      if (user) {
        callback({ success: true });
      } else {
        callback({ success: false });
      }
    }).catch((err) => {
      console.error('Error finding user:', err);
      callback({ success: false });
    }); 
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