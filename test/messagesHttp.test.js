const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createMessagesRouter } = require('../src/interfaces/http/routes/messages.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const { BadRequestError } = require('../src/shared/errors');

const VALID_TOKEN = 'valid-token';
const FAKE_USER = { id: 'U1', username: 'alice' };

function makeJwtMock() {
  return {
    verify(token, _secret, cb) {
      if (token === VALID_TOKEN) return cb(null, FAKE_USER);
      return cb(new Error('invalid'));
    },
  };
}

function buildApp({ messagingService, mongoConnected = true, withAuth = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };

  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth: realRequireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });
  const requireAuth = withAuth ? realRequireAuth : (req, _res, next) => {
    req.user = FAKE_USER;
    next();
  };

  const router = createMessagesRouter({
    messagingService,
    mongoose: fakeMongoose,
    requireAuth,
  });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function authed(req) {
  return req.set('Authorization', `Bearer ${VALID_TOKEN}`);
}

function makeService(overrides = {}) {
  return {
    checkMessagesExist: async () => ({ exists: false }),
    getLatestMessageNumber: async () => ({ messageNumber: -1 }),
    markMessagesSeen: async () => ({ updatedCount: 0 }),
    ...overrides,
  };
}

test('POST /messages/check 200 returns exists flag', async () => {
  const seen = [];
  const svc = makeService({
    checkMessagesExist: async (input) => {
      seen.push(input);
      return { exists: true };
    },
  });
  const app = buildApp({ messagingService: svc });
  const res = await authed(request(app).post('/messages/check')).send({ targetUserId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, exists: true });
  assert.deepEqual(seen, [{ userId: 'U1', targetUserId: 'U2' }]);
});

test('POST /messages/check 401 without bearer token', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await request(app).post('/messages/check').send({ targetUserId: 'U2' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /messages/check 401 with invalid token', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await request(app)
    .post('/messages/check')
    .set('Authorization', 'Bearer wrong')
    .send({ targetUserId: 'U2' });
  assert.equal(res.status, 401);
});

test('POST /messages/check 400 when targetUserId missing', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await authed(request(app).post('/messages/check')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/check 400 when targetUserId wrong type', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await authed(request(app).post('/messages/check')).send({ targetUserId: 123 });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/check 503 when DB unavailable', async () => {
  const app = buildApp({ messagingService: makeService(), mongoConnected: false });
  const res = await authed(request(app).post('/messages/check')).send({ targetUserId: 'U2' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('POST /messages/latest-number 200 returns messageNumber', async () => {
  const svc = makeService({
    getLatestMessageNumber: async () => ({ messageNumber: 7 }),
  });
  const app = buildApp({ messagingService: svc });
  const res = await authed(request(app).post('/messages/latest-number')).send({ targetUserId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, messageNumber: 7 });
});

test('POST /messages/latest-number 200 returns -1 for new conversation', async () => {
  const svc = makeService({
    getLatestMessageNumber: async () => ({ messageNumber: -1 }),
  });
  const app = buildApp({ messagingService: svc });
  const res = await authed(request(app).post('/messages/latest-number')).send({ targetUserId: 'U9' });
  assert.equal(res.status, 200);
  assert.equal(res.body.messageNumber, -1);
});

test('POST /messages/latest-number 401 without token', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await request(app).post('/messages/latest-number').send({ targetUserId: 'U2' });
  assert.equal(res.status, 401);
});

test('POST /messages/latest-number 400 when targetUserId missing', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await authed(request(app).post('/messages/latest-number')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/mark-seen 200 returns updatedCount', async () => {
  const seen = [];
  const svc = makeService({
    markMessagesSeen: async (input) => {
      seen.push(input);
      return { updatedCount: 3 };
    },
  });
  const app = buildApp({ messagingService: svc });
  const res = await authed(request(app).post('/messages/mark-seen')).send({ targetUserId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, updatedCount: 3 });
  assert.deepEqual(seen, [{ userId: 'U1', targetUserId: 'U2' }]);
});

test('POST /messages/mark-seen 401 without token', async () => {
  const app = buildApp({ messagingService: makeService() });
  const res = await request(app).post('/messages/mark-seen').send({ targetUserId: 'U2' });
  assert.equal(res.status, 401);
});

test('POST /messages/mark-seen 400 when validation fails downstream', async () => {
  const svc = makeService({
    markMessagesSeen: async () => {
      throw new BadRequestError('Missing required field: targetUserId', 'validation_error', 'targetUserId');
    },
  });
  const app = buildApp({ messagingService: svc });
  // Bypass router-level validateBody by sending a non-empty string and forcing the service to throw.
  const res = await authed(request(app).post('/messages/mark-seen')).send({ targetUserId: 'X' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/mark-seen 503 when DB unavailable', async () => {
  const app = buildApp({ messagingService: makeService(), mongoConnected: false });
  const res = await authed(request(app).post('/messages/mark-seen')).send({ targetUserId: 'U2' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('createMessagingService.markMessagesSeen emits messageSeenUpdate via notifier', async () => {
  const { createMessagingService } = require('../src/modules/messaging/application/messagingService');
  const events = [];
  const Message = {
    updateMany: async () => ({ modifiedCount: 2 }),
  };
  const notifier = {
    emitToUser: (userId, event, payload) => {
      events.push({ userId, event, payload });
    },
  };
  const svc = createMessagingService({
    Message,
    makeConversationKey: (a, b) => [a, b].sort().join('_'),
    ensureConversationSequence: async () => ({ lastMessageNumber: -1 }),
    notifier,
  });

  const result = await svc.markMessagesSeen({ userId: 'U1', targetUserId: 'U2' });
  assert.deepEqual(result, { updatedCount: 2 });
  assert.equal(events.length, 1);
  assert.equal(events[0].userId, 'U2');
  assert.equal(events[0].event, 'messageSeenUpdate');
  assert.deepEqual(events[0].payload, { userId: 'U1', targetUserId: 'U2' });
});

test('createMessagingService.getLatestMessageNumber returns -1 when sequence is new', async () => {
  const { createMessagingService } = require('../src/modules/messaging/application/messagingService');
  const svc = createMessagingService({
    Message: { updateMany: async () => ({ modifiedCount: 0 }) },
    makeConversationKey: (a, b) => [a, b].sort().join('_'),
    ensureConversationSequence: async () => ({}),
    notifier: { emitToUser: () => {} },
  });
  const out = await svc.getLatestMessageNumber({ userId: 'U1', targetUserId: 'U2' });
  assert.deepEqual(out, { messageNumber: -1 });
});

test('createMessagingService throws BadRequestError when targetUserId is empty', async () => {
  const { createMessagingService } = require('../src/modules/messaging/application/messagingService');
  const svc = createMessagingService({
    Message: { findOne: async () => null },
    makeConversationKey: (a, b) => [a, b].sort().join('_'),
    ensureConversationSequence: async () => ({}),
    notifier: { emitToUser: () => {} },
  });
  await assert.rejects(
    svc.checkMessagesExist({ userId: 'U1', targetUserId: '' }),
    (err) => err.status === 400 && err.code === 'validation_error',
  );
});
