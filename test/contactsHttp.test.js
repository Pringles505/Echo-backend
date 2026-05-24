const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createContactsRouter } = require('../src/interfaces/http/routes/contacts.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const { createNoopNotifier } = require('../src/interfaces/socket/notifier');
const {
  BadRequestError,
  NotFoundError,
  ConflictError,
} = require('../src/shared/errors');

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

function buildApp({ contactsService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };

  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });

  app.use(createContactsRouter({
    contactsService,
    mongoose: fakeMongoose,
    requireAuth,
    notifier: createNoopNotifier(),
  }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function authed(req) {
  return req.set('Authorization', `Bearer ${VALID_TOKEN}`);
}

function makeService(overrides = {}) {
  return {
    addFriend: async () => ({ added: true }),
    removeFriend: async () => ({ removed: true }),
    ...overrides,
  };
}

test('POST /contacts/add-friend returns 200 on success', async () => {
  const seen = [];
  const svc = makeService({
    addFriend: async (input) => { seen.push(input); return { added: true }; },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true });
  assert.deepEqual(seen, [{ userId: 'U1', friendId: 'U2' }]);
});

test('POST /contacts/add-friend 401 without token', async () => {
  const app = buildApp({ contactsService: makeService() });
  const res = await request(app).post('/contacts/add-friend').send({ friendId: 'U2' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /contacts/add-friend 401 with invalid token', async () => {
  const app = buildApp({ contactsService: makeService() });
  const res = await request(app)
    .post('/contacts/add-friend')
    .set('Authorization', 'Bearer wrong')
    .send({ friendId: 'U2' });
  assert.equal(res.status, 401);
});

test('POST /contacts/add-friend 400 when friendId missing', async () => {
  const app = buildApp({ contactsService: makeService() });
  const res = await authed(request(app).post('/contacts/add-friend')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /contacts/add-friend 400 when adding self', async () => {
  const svc = makeService({
    addFriend: async () => {
      throw new BadRequestError('Cannot add yourself as a friend', 'self_friend');
    },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'U1' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'self_friend');
});

test('POST /contacts/add-friend 404 when friend does not exist', async () => {
  const svc = makeService({
    addFriend: async () => { throw new NotFoundError('User(s) not found', 'user_not_found'); },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'NOPE' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

test('POST /contacts/add-friend 409 when already friends', async () => {
  const svc = makeService({
    addFriend: async () => { throw new ConflictError('Already friends', 'already_friends'); },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'already_friends');
});

test('POST /contacts/add-friend 503 when DB unavailable', async () => {
  const app = buildApp({ contactsService: makeService(), mongoConnected: false });
  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('POST /contacts/remove-friend returns 200 on success', async () => {
  const seen = [];
  const svc = makeService({
    removeFriend: async (input) => { seen.push(input); return { removed: true }; },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/remove-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true });
  assert.deepEqual(seen, [{ userId: 'U1', friendId: 'U2' }]);
});

test('POST /contacts/remove-friend 401 without token', async () => {
  const app = buildApp({ contactsService: makeService() });
  const res = await request(app).post('/contacts/remove-friend').send({ friendId: 'U2' });
  assert.equal(res.status, 401);
});

test('POST /contacts/remove-friend 400 when friendId missing', async () => {
  const app = buildApp({ contactsService: makeService() });
  const res = await authed(request(app).post('/contacts/remove-friend')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /contacts/remove-friend 404 when user not found', async () => {
  const svc = makeService({
    removeFriend: async () => { throw new NotFoundError('User(s) not found', 'user_not_found'); },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/remove-friend')).send({ friendId: 'NOPE' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

test('POST /contacts/remove-friend 409 when not friends', async () => {
  const svc = makeService({
    removeFriend: async () => { throw new ConflictError('Not friends', 'not_friends'); },
  });
  const app = buildApp({ contactsService: svc });
  const res = await authed(request(app).post('/contacts/remove-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'not_friends');
});

test('createContactsRouter notifies both participants on add (via notifier)', async () => {
  const { createContactsService } = require('../src/modules/contacts/application/contactsService');

  const users = {
    U1: { id: 'U1', username: 'alice', friends: [], save: async () => {} },
    U2: { id: 'U2', username: 'bob', friends: [], save: async () => {} },
  };
  const User = {
    findOne: async ({ id }) => users[id] || null,
  };
  const notifier = createNoopNotifier();
  const svc = createContactsService({ User, notifier });

  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });
  const app = express();
  app.use(express.json());
  app.use(createContactsRouter({
    contactsService: svc,
    mongoose: { connection: { readyState: 1 } },
    requireAuth,
    notifier,
  }));
  app.use(notFoundHandler);
  app.use(errorHandler);

  const res = await authed(request(app).post('/contacts/add-friend')).send({ friendId: 'U2' });
  assert.equal(res.status, 200);
  assert.deepEqual(users.U1.friends, ['U2']);
  const events = notifier.events.filter((e) => e.event === 'friendAdded');
  assert.equal(events.length, 2);
  const targets = events.map((e) => e.userId).sort();
  assert.deepEqual(targets, ['U1', 'U2']);
});
