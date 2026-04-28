/**
 * @module server
 * @description Composition root for Echo Backend.
 * Wires dependencies, initializes database, and establishes Socket.IO handlers.
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { loadEnv } = require('./src/config/loadEnv');
const { connectMongo } = require('./src/infrastructure/persistence/mongoose/connect');
const {
  createModels,
  syncKeyPackageIndexes,
} = require('./src/infrastructure/persistence/mongoose/models');
const { createAuthService } = require('./src/modules/auth/application/authService');
const { createCallEventService } = require('./src/modules/calls/application/callEventService');
const { createSequenceService } = require('./src/interfaces/socket/context/sequences');
const { createOpkLimiterService } = require('./src/interfaces/socket/context/opkLimiter');
const { saveProfilePicture } = require('./src/interfaces/socket/context/profilePictureStorage');
const { registerSocketHandlers } = require('./src/interfaces/socket/registerSocketHandlers');
const { healthRouter } = require('./src/interfaces/http/routes/health.route');
const { authRouter } = require('./src/interfaces/http/routes/auth.route');
const { messagesRouter } = require('./src/interfaces/http/routes/messages.route');
const { usersRouter } = require('./src/interfaces/http/routes/users.route');
const { contactsRouter } = require('./src/interfaces/http/routes/contacts.route');
const { groupsRouter } = require('./src/interfaces/http/routes/groups.route');
const { callsRouter } = require('./src/interfaces/http/routes/calls.route');
const { keysRouter } = require('./src/interfaces/http/routes/keys.route');
const { setupSwagger } = require('./src/interfaces/http/swagger');
const {
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  normalizeOneTimePreKeysPayload,
  computeOpkReplenishNeeded,
  dedupeIncomingOpks,
  capToRemainingCapacity,
  estimateOpkCountAfterConsume,
} = require('./opkPolicy');
const {
  CORS_ORIGINS,
  JSON_LIMIT,
  PORT,
  SOCKET_PING_INTERVAL,
  SOCKET_PING_TIMEOUT,
} = require('./src/shared/constants');

loadEnv();

const userSocketMap = {};

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: CORS_ORIGINS,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
  pingInterval: SOCKET_PING_INTERVAL,
  pingTimeout: SOCKET_PING_TIMEOUT,
});

app.use(cors({
  origin: CORS_ORIGINS,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(express.json({ limit: JSON_LIMIT }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(healthRouter);
app.use(authRouter);
app.use(messagesRouter);
app.use(usersRouter);
app.use(contactsRouter);
app.use(groupsRouter);
app.use(callsRouter);
app.use(keysRouter);
setupSwagger(app);

connectMongo(mongoose).catch((err) => {
  console.error('Error connecting to MongoDB', err);
});

const {
  Message,
  User,
  MessageSequence,
  OpkRequestLog,
  Call,
  Group,
  GroupMember,
  GroupSequence,
  KeyPackage,
} = createModels(mongoose);

const authService = createAuthService({
  User,
  bcrypt,
  jwt,
  normalizeOneTimePreKeysPayload,
  OPK_MAX_STORED,
});

const sequenceService = createSequenceService({ Message, MessageSequence, GroupSequence });
const callEventService = createCallEventService({ io, userSocketMap, Call, Message, User });
const opkLimiter = createOpkLimiterService(OpkRequestLog);

if (mongoose.connection.readyState === 1) {
  void syncKeyPackageIndexes(KeyPackage);
} else {
  mongoose.connection.once('open', () => {
    void syncKeyPackageIndexes(KeyPackage);
  });
}

const authenticate = (socket, next) => {
  const token = socket.handshake?.auth?.token;
  if (!token) {
    console.warn('No token provided, allowing unauthenticated access for login/register');
    socket.user = null;
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('unauthorized'));
    if (!decoded?.id) return next(new Error('unauthorized'));

    userSocketMap[decoded.id] = socket.id;
    socket.user = decoded;
    return next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {
  console.log(`A user connected with socket ID: ${socket.id}`);

  registerSocketHandlers({
    socket,
    io,
    userSocketMap,
    models: {
      Message,
      User,
      MessageSequence,
      OpkRequestLog,
      Call,
      Group,
      GroupMember,
      GroupSequence,
      KeyPackage,
    },
    services: {
      makeConversationKey: sequenceService.makeConversationKey,
      ensureConversationSequence: sequenceService.ensureConversationSequence,
      ensureGroupSequence: sequenceService.ensureGroupSequence,
      createCallEventMessage: callEventService.createCallEventMessage,
      saveProfilePicture,
    },
    authService,
    bcrypt,
    opkPolicy: {
      OPK_MAX_STORED,
      OPK_UPLOAD_MAX,
      normalizeOneTimePreKeysPayload,
      computeOpkReplenishNeeded,
      dedupeIncomingOpks,
      capToRemainingCapacity,
      estimateOpkCountAfterConsume,
    },
    opkLimiter,
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`listening on *:${PORT}`);
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
