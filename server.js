/**
 * @module server
 * @description Composition root for Echo Backend.
 * Wires dependencies, initializes database, and establishes Socket.IO handlers.
 */

const express = require('express');
const helmet = require('helmet');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { loadEnv, validateRuntimeEnv } = require('./src/config/loadEnv');
const { connectMongo } = require('./src/infrastructure/persistence/mongoose/connect');
const {
  createModels,
  syncKeyPackageIndexes,
} = require('./src/infrastructure/persistence/mongoose/models');
const { createAuthService } = require('./src/modules/auth/application/authService');
const { createCallEventService } = require('./src/modules/calls/application/callEventService');
const { createKeysService } = require('./src/modules/keys/application/keysService');
const { createSequenceService } = require('./src/interfaces/socket/context/sequences');
const { createOpkLimiterService } = require('./src/interfaces/socket/context/opkLimiter');
const { saveProfilePicture } = require('./src/interfaces/socket/context/profilePictureStorage');
const { createSocketNotifier } = require('./src/interfaces/socket/notifier');
const { registerSocketHandlers } = require('./src/interfaces/socket/registerSocketHandlers');
const { healthRouter } = require('./src/interfaces/http/routes/health.route');
const { createAuthRouter } = require('./src/interfaces/http/routes/auth.route');
const messagesRouteModule = require('./src/interfaces/http/routes/messages.route');
const usersRouteModule = require('./src/interfaces/http/routes/users.route');
const contactsRouteModule = require('./src/interfaces/http/routes/contacts.route');
const groupsRouteModule = require('./src/interfaces/http/routes/groups.route');
const callsRouteModule = require('./src/interfaces/http/routes/calls.route');
const keysRouteModule = require('./src/interfaces/http/routes/keys.route');
const { createPairingRouter } = require('./src/interfaces/http/routes/pairing.route');
const { createDevicesRouter } = require('./src/interfaces/http/routes/devices.route');
const { createEnvelopesRouter } = require('./src/interfaces/http/routes/envelopes.route');
const { createSyncRouter } = require('./src/interfaces/http/routes/sync.route');
const { createPairingService } = require('./src/modules/devices/application/pairingService');
const { createDeviceManagementService } = require('./src/modules/devices/application/deviceManagementService');
const { createDeviceSyncService } = require('./src/modules/deviceSync/application/deviceSyncService');
const { setupSwagger } = require('./src/interfaces/http/swagger');
const { createAuthMiddleware } = require('./src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('./src/interfaces/http/middleware/errorHandlers');
const {
  loginLimiter,
  registerLimiter,
  searchLimiter,
  keyBundleLimiter,
} = require('./src/interfaces/http/middleware/rateLimit');
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
  API_VERSION_PREFIX,
  API_VERSION_HEADER_VALUE,
  JSON_LIMIT,
  PORT,
  SOCKET_PING_INTERVAL,
  SOCKET_PING_TIMEOUT,
} = require('./src/shared/constants');

loadEnv();
validateRuntimeEnv();

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

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(cors({
  origin: CORS_ORIGINS,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.use(express.json({ limit: JSON_LIMIT }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const mongoConnectionPromise = connectMongo(mongoose);
if (require.main !== module) {
  mongoConnectionPromise.catch((err) => {
    console.error('Error connecting to MongoDB', err);
  });
}

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
  Device,
  PairingSession,
  MessageEnvelope,
  DeviceSyncSession,
} = createModels(mongoose);

const authService = createAuthService({
  User,
  Device,
  bcrypt,
  jwt,
  normalizeOneTimePreKeysPayload,
  OPK_MAX_STORED,
});

const pairingService = createPairingService({ PairingSession, Device, User, authService });
const deviceManagementService = createDeviceManagementService({ Device, MessageEnvelope, User, io });
const deviceSyncService = createDeviceSyncService({ DeviceSyncSession, User, Device, authService });

const sequenceService = createSequenceService({ Message, MessageSequence, GroupSequence });
const callEventService = createCallEventService({ io, userSocketMap, Call, Message, User });
const opkLimiter = createOpkLimiterService(OpkRequestLog);
const notifier = createSocketNotifier({ io, userSocketMap });
const { requireAuth, optionalAuth } = createAuthMiddleware({ jwt, Device });

const opkPolicyDeps = {
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  normalizeOneTimePreKeysPayload,
  computeOpkReplenishNeeded,
  dedupeIncomingOpks,
  capToRemainingCapacity,
  estimateOpkCountAfterConsume,
};

const keysService = createKeysService({
  User,
  opkPolicy: opkPolicyDeps,
  opkLimiter,
  notifier,
});

const httpDeps = {
  mongoose,
  jwt,
  bcrypt,
  io,
  userSocketMap,
  notifier,
  requireAuth,
  optionalAuth,
  searchLimiter,
  keyBundleLimiter,
  keysService,
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
    authService,
    sequenceService,
    callEventService,
    saveProfilePicture,
  },
  opkPolicy: opkPolicyDeps,
  rateLimit: {
    loginLimiter,
    registerLimiter,
    searchLimiter,
    keyBundleLimiter,
  },
};

function pickRouter(mod, factoryName, legacyName, factoryDeps = httpDeps) {
  if (typeof mod[factoryName] === 'function') {
    return mod[factoryName](factoryDeps);
  }
  if (mod[legacyName]) return mod[legacyName];
  throw new Error(`Route module is missing both ${factoryName}() and ${legacyName}`);
}

const authRouter = createAuthRouter({
  authService,
  mongoose,
  registerLimiter,
  loginLimiter,
});

const messagesRouter = pickRouter(messagesRouteModule, 'createMessagesRouter', 'messagesRouter');
const usersRouter = pickRouter(usersRouteModule, 'createUsersRouter', 'usersRouter');
const contactsRouter = pickRouter(contactsRouteModule, 'createContactsRouter', 'contactsRouter');
const groupsRouter = pickRouter(groupsRouteModule, 'createGroupsRouter', 'groupsRouter');
const callsRouter = pickRouter(callsRouteModule, 'createCallsRouter', 'callsRouter');
const keysRouter = pickRouter(keysRouteModule, 'createKeysRouter', 'keysRouter');

const pairingRouter = createPairingRouter({ pairingService, mongoose, requireAuth });
const devicesRouter = createDevicesRouter({ deviceManagementService, mongoose, requireAuth });
const envelopesRouter = createEnvelopesRouter({ deviceManagementService, mongoose, requireAuth });
const syncRouter = createSyncRouter({ deviceSyncService, mongoose, requireAuth, optionalAuth });

const mountHttpRoutes = (target) => {
  target.use(healthRouter);
  target.use(authRouter);
  target.use(messagesRouter);
  target.use(usersRouter);
  target.use(contactsRouter);
  target.use(groupsRouter);
  target.use(callsRouter);
  target.use(keysRouter);
  target.use(pairingRouter);
  target.use(devicesRouter);
  target.use(envelopesRouter);
  target.use(syncRouter);
};

mountHttpRoutes(app);

const apiV1Router = express.Router();
apiV1Router.use((_req, res, next) => {
  res.setHeader('X-API-Version', API_VERSION_HEADER_VALUE);
  next();
});
mountHttpRoutes(apiV1Router);
app.use(API_VERSION_PREFIX, apiV1Router);

setupSwagger(app, {
  basePath: API_VERSION_PREFIX,
  includeLegacy: true,
});
app.use(notFoundHandler);
app.use(errorHandler);

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
    socket.user = null;
    return next();
  }

  if (typeof token !== 'string' || token.trim().length === 0) {
    return next(new Error('unauthorized'));
  }

  jwt.verify(token.trim(), process.env.JWT_SECRET, async (err, decoded) => {
    if (err) return next(new Error('unauthorized'));
    if (!decoded?.id) return next(new Error('unauthorized'));

    if (decoded.deviceId) {
      try {
        const device = await Device.findOne({ deviceId: decoded.deviceId }).lean();
        if (!device) return next(new Error('device_not_registered'));
        if (device.isRevoked) return next(new Error('device_revoked'));
        if (String(device.parentUserId) !== String(decoded.id)) {
          return next(new Error('device_forbidden'));
        }
      } catch {
        return next(new Error('unauthorized'));
      }
    }

    userSocketMap[decoded.id] = socket.id;
    socket.user = decoded;
    return next();
  });
};

io.use(authenticate);

io.on('connection', (socket) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log('Socket client connected');
  }

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
      Device,
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
    deviceSyncService,
  });
});

if (require.main === module) {
  mongoConnectionPromise
    .then(() => {
      server.listen(PORT, () => {
        console.log(`listening on *:${PORT}`);
      });
    })
    .catch((err) => {
      console.error('Error connecting to MongoDB', err);
      process.exitCode = 1;
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
