const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createUsersRouter } = require('../src/interfaces/http/routes/users.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const {
  BadRequestError,
  UnauthorizedError,
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

function buildApp({ userProfileService, mongoConnected = true, withAuth = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };

  // Real requireAuth wired against a JWT mock that accepts VALID_TOKEN only.
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = previousSecret || 'test-secret';
  const { requireAuth: realRequireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });

  const requireAuth = withAuth ? realRequireAuth : (req, _res, next) => {
    req.user = FAKE_USER;
    next();
  };

  const router = createUsersRouter({
    userProfileService,
    mongoose: fakeMongoose,
    requireAuth,
    notifier: { listOnlineUserIds: () => [] },
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
    searchUser: async () => ({ id: 'U2', username: 'bob' }),
    getUserById: async () => ({ id: 'U2', username: 'bob' }),
    updateProfile: async () => ({ id: 'U1', username: 'alice' }),
    deleteAccount: async () => ({ deleted: true }),
    listOnlineUserIds: () => ['U1', 'U2'],
    ...overrides,
  };
}

// ---------------------------------------------------------------- /users/search

test('POST /users/search returns 200 with user on success', async () => {
  const seen = [];
  const svc = makeService({
    searchUser: async (input) => {
      seen.push(input);
      return { id: 'U2', username: 'bob' };
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).post('/users/search')).send({ searchTerm: 'bob' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, user: { id: 'U2', username: 'bob' } });
  assert.deepEqual(seen, [{ searchTerm: 'bob' }]);
});

test('POST /users/search 401 when no bearer token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app).post('/users/search').send({ searchTerm: 'bob' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /users/search 401 with invalid token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app)
    .post('/users/search')
    .set('Authorization', 'Bearer wrong')
    .send({ searchTerm: 'bob' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /users/search 400 when searchTerm missing', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await authed(request(app).post('/users/search')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /users/search 404 when user not found', async () => {
  const svc = makeService({
    searchUser: async () => { throw new NotFoundError('User not found', 'user_not_found'); },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).post('/users/search')).send({ searchTerm: 'nope' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

test('POST /users/search 503 when DB unavailable', async () => {
  const app = buildApp({ userProfileService: makeService(), mongoConnected: false });
  const res = await authed(request(app).post('/users/search')).send({ searchTerm: 'bob' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

// ---------------------------------------------------------------- /users/online

test('GET /users/online returns 200 with snapshot', async () => {
  const svc = makeService({ listOnlineUserIds: () => ['U1', 'U7'] });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).get('/users/online'));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, onlineUsers: ['U1', 'U7'] });
});

test('GET /users/online 401 without token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app).get('/users/online');
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------- /users/:userId

test('GET /users/:userId returns 200 with profile', async () => {
  const svc = makeService({
    getUserById: async ({ userId }) => ({ id: userId, username: 'bob', friends: [] }),
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).get('/users/U2'));
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.user.id, 'U2');
});

test('GET /users/:userId 404 when missing', async () => {
  const svc = makeService({
    getUserById: async () => { throw new NotFoundError('User not found', 'user_not_found'); },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).get('/users/UNKNOWN'));
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

test('GET /users/online is matched before /users/:userId (route ordering)', async () => {
  // If /users/:userId were registered first, "online" would be captured
  // as a userId param and we'd hit getUserById instead. This test guards
  // the ordering inside createUsersRouter.
  let getUserCalled = false;
  const svc = makeService({
    listOnlineUserIds: () => ['U1'],
    getUserById: async () => { getUserCalled = true; return { id: 'X' }; },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).get('/users/online'));
  assert.equal(res.status, 200);
  assert.equal(getUserCalled, false);
  assert.deepEqual(res.body.onlineUsers, ['U1']);
});

test('GET /users/:userId 401 without token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app).get('/users/U2');
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------- /users/profile/update

test('PUT /users/profile/update returns 200 with updated user', async () => {
  const seen = [];
  const svc = makeService({
    updateProfile: async (input) => {
      seen.push(input);
      return { id: 'U1', username: 'alice2', aboutme: 'hi' };
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).put('/users/profile/update'))
    .send({ username: 'alice2', aboutme: 'hi' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.username, 'alice2');
  assert.equal(seen[0].userId, 'U1');
  assert.equal(seen[0].changes.username, 'alice2');
});

test('PUT /users/profile/update 400 when newPassword without oldPassword', async () => {
  const svc = makeService({
    updateProfile: async () => {
      throw new BadRequestError(
        'oldPassword is required when newPassword is provided',
        'old_password_required'
      );
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).put('/users/profile/update'))
    .send({ newPassword: 'new' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'old_password_required');
});

test('PUT /users/profile/update 401 on wrong oldPassword', async () => {
  const svc = makeService({
    updateProfile: async () => {
      throw new UnauthorizedError('Old password is incorrect', 'invalid_credentials');
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).put('/users/profile/update'))
    .send({ oldPassword: 'x', newPassword: 'y' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'invalid_credentials');
});

test('PUT /users/profile/update 409 on duplicate username', async () => {
  const svc = makeService({
    updateProfile: async () => {
      throw new ConflictError('Username already taken', 'username_conflict');
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).put('/users/profile/update'))
    .send({ username: 'taken' });
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'username_conflict');
});

test('PUT /users/profile/update 401 without token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app).put('/users/profile/update').send({ aboutme: 'x' });
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------- /users/account/delete

test('DELETE /users/account/delete 200 when password matches', async () => {
  const seen = [];
  const svc = makeService({
    deleteAccount: async (input) => {
      seen.push(input);
      return { deleted: true };
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).delete('/users/account/delete'))
    .send({ password: 'secret' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true });
  assert.deepEqual(seen, [{ userId: 'U1', password: 'secret' }]);
});

test('DELETE /users/account/delete 400 when password missing (SEC-002)', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await authed(request(app).delete('/users/account/delete')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('DELETE /users/account/delete 401 when password wrong', async () => {
  const svc = makeService({
    deleteAccount: async () => {
      throw new UnauthorizedError('Password is incorrect', 'invalid_credentials');
    },
  });
  const app = buildApp({ userProfileService: svc });
  const res = await authed(request(app).delete('/users/account/delete'))
    .send({ password: 'wrong' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'invalid_credentials');
});

test('DELETE /users/account/delete 401 without token', async () => {
  const app = buildApp({ userProfileService: makeService() });
  const res = await request(app).delete('/users/account/delete').send({ password: 'x' });
  assert.equal(res.status, 401);
});
