const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
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

const messageSchema = new mongoose.Schema({
  text: String,
  createdAt: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);

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