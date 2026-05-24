const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createAuthRouter } = require('../src/interfaces/http/routes/auth.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const {
  BadRequestError,
  UnauthorizedError,
} = require('../src/shared/errors');

const VALID_TOKEN = 'valid-token';
const FAKE_USER = { id: 'U1', username: 'alice' };

function makeJwtMock() {
  return {
    verify(token, _secret, cb) {
      if (token === VALID_TOKEN) return cb(null, FAKE_USER);
      return cb(new Error('invalid'));
    },
    sign() { return 'new.jwt.token'; },
  };
}

function buildApp({ authService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });

  app.use(createAuthRouter({
    authService,
    mongoose: fakeMongoose,
    requireAuth,
  }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function authed(req) {
  return req.set('Authorization', `Bearer ${VALID_TOKEN}`);
}

function makeSvc(overrides = {}) {
  return {
    register: async () => ({}),
    login: async () => ({}),
    refresh: async () => ({
      token: 'new.access.jwt',
      refreshToken: 'new.refresh.opaque',
      userId: 'U1',
      expiresIn: 3600,
    }),
    logout: async () => ({ ok: true }),
    ...overrides,
  };
}

test('POST /auth/refresh 200 with new token+refreshToken on rotation', async () => {
  const seen = [];
  const svc = makeSvc({
    refresh: async (input) => {
      seen.push(input);
      return {
        token: 'new.access.jwt',
        refreshToken: 'rotated.refresh',
        userId: 'U1',
        expiresIn: 3600,
      };
    },
  });
  const app = buildApp({ authService: svc });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'old.refresh' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.token, 'new.access.jwt');
  assert.equal(res.body.refreshToken, 'rotated.refresh');
  assert.equal(res.body.userId, 'U1');
  assert.equal(res.body.expiresIn, 3600);
  assert.equal(seen[0].refreshToken, 'old.refresh');
});

test('POST /auth/refresh 400 when refreshToken missing in body', async () => {
  const app = buildApp({ authService: makeSvc() });
  const res = await request(app).post('/auth/refresh').send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /auth/refresh 401 when refresh token is not found', async () => {
  const svc = makeSvc({
    refresh: async () => {
      throw new UnauthorizedError('Refresh token is invalid', 'refresh_token_invalid');
    },
  });
  const app = buildApp({ authService: svc });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'bogus' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'refresh_token_invalid');
});

test('POST /auth/refresh 401 when refresh token has expired', async () => {
  const svc = makeSvc({
    refresh: async () => {
      throw new UnauthorizedError('Refresh token has expired', 'refresh_token_expired');
    },
  });
  const app = buildApp({ authService: svc });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'old' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'refresh_token_expired');
});

test('POST /auth/refresh 401 when refresh token reuse detected', async () => {
  const svc = makeSvc({
    refresh: async () => {
      throw new UnauthorizedError('Refresh token reuse detected', 'refresh_token_reused');
    },
  });
  const app = buildApp({ authService: svc });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'revoked' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'refresh_token_reused');
});

test('POST /auth/refresh is public (does not require Authorization header)', async () => {
  const svc = makeSvc();
  const app = buildApp({ authService: svc });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'r' });
  assert.equal(res.status, 200);
});

test('POST /auth/refresh 503 when DB unavailable', async () => {
  const app = buildApp({ authService: makeSvc(), mongoConnected: false });
  const res = await request(app).post('/auth/refresh').send({ refreshToken: 'r' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('POST /auth/logout 200 when authenticated with valid refresh token', async () => {
  const seen = [];
  const svc = makeSvc({
    logout: async (input) => {
      seen.push(input);
      return { ok: true };
    },
  });
  const app = buildApp({ authService: svc });
  const res = await authed(request(app).post('/auth/logout'))
    .send({ refreshToken: 'to-revoke' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true });
  assert.deepEqual(seen[0], { refreshToken: 'to-revoke', userId: 'U1' });
});

test('POST /auth/logout 200 idempotent when token already revoked or missing', async () => {
  const svc = makeSvc({ logout: async () => ({ ok: true }) });
  const app = buildApp({ authService: svc });
  const res = await authed(request(app).post('/auth/logout'))
    .send({ refreshToken: 'already-gone' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
});

test('POST /auth/logout 401 without access token', async () => {
  const app = buildApp({ authService: makeSvc() });
  const res = await request(app).post('/auth/logout').send({ refreshToken: 'r' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /auth/logout 400 when refreshToken missing in body', async () => {
  const app = buildApp({ authService: makeSvc() });
  const res = await authed(request(app).post('/auth/logout')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});
