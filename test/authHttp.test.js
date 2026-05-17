const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createAuthRouter } = require('../src/interfaces/http/routes/auth.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({ authService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  app.use(createAuthRouter({ authService, mongoose: fakeMongoose }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

test('POST /auth/register returns 201 with userId on success', async () => {
  const calls = [];
  const authService = {
    register: async (input) => {
      calls.push(input);
      return { userId: 'ABCDE' };
    },
    login: async () => ({}),
  };
  const app = buildApp({ authService });

  const res = await request(app)
    .post('/auth/register')
    .send({
      username: 'alice',
      password: 'secret',
      keyBundle: { publicSignedPreKey: ['k', 's'], oneTimePreKeys: [] },
    });

  assert.equal(res.status, 201);
  assert.deepEqual(res.body, { success: true, userId: 'ABCDE' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].username, 'alice');
});

test('POST /auth/register returns 400 when required fields missing', async () => {
  const app = buildApp({ authService: { register: async () => ({}), login: async () => ({}) } });
  const res = await request(app).post('/auth/register').send({ username: 'alice' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /auth/register returns 409 on duplicate username (Mongo 11000)', async () => {
  const dupErr = Object.assign(new Error('dup'), { code: 11000, keyPattern: { username: 1 } });
  const authService = {
    register: async () => { throw dupErr; },
    login: async () => ({}),
  };
  const app = buildApp({ authService });

  const res = await request(app)
    .post('/auth/register')
    .send({
      username: 'taken',
      password: 'p',
      keyBundle: { publicSignedPreKey: ['k', 's'], oneTimePreKeys: [] },
    });

  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'username_conflict');
});

test('POST /auth/register surfaces typed HttpServiceError from service', async () => {
  const { BadRequestError } = require('../src/shared/errors');
  const authService = {
    register: async () => { throw new BadRequestError('Bad bundle', 'invalid_key_bundle'); },
    login: async () => ({}),
  };
  const app = buildApp({ authService });
  const res = await request(app)
    .post('/auth/register')
    .send({ username: 'a', password: 'p', keyBundle: {} });

  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'invalid_key_bundle');
});

test('POST /auth/register returns 503 when DB is unavailable', async () => {
  const app = buildApp({
    authService: { register: async () => ({ userId: 'x' }), login: async () => ({}) },
    mongoConnected: false,
  });
  const res = await request(app)
    .post('/auth/register')
    .send({ username: 'a', password: 'p', keyBundle: {} });

  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('POST /auth/login returns 200 with token + refreshToken on success', async () => {
  const authService = {
    register: async () => ({}),
    login: async () => ({
      success: true,
      token: 'jwt.token',
      refreshToken: 'r3fr3sh',
      userId: 'U1',
      expiresIn: 3600,
    }),
  };
  const app = buildApp({ authService });

  const res = await request(app).post('/auth/login').send({ username: 'a', password: 'p' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.token, 'jwt.token');
  assert.equal(res.body.refreshToken, 'r3fr3sh');
  assert.equal(res.body.userId, 'U1');
  assert.equal(res.body.expiresIn, 3600);
});

test('POST /auth/login backwards-compatible when service omits refreshToken (legacy services)', async () => {
  const authService = {
    register: async () => ({}),
    login: async () => ({ success: true, token: 'jwt.token', userId: 'U1' }),
  };
  const app = buildApp({ authService });

  const res = await request(app).post('/auth/login').send({ username: 'a', password: 'p' });
  assert.equal(res.status, 200);
  assert.equal(res.body.token, 'jwt.token');
  assert.equal(res.body.refreshToken, undefined);
  assert.equal(res.body.expiresIn, undefined);
});

test('POST /auth/login returns 401 on invalid credentials (service returns success:false)', async () => {
  const authService = {
    register: async () => ({}),
    login: async () => ({ success: false, error: 'Invalid username or password' }),
  };
  const app = buildApp({ authService });

  const res = await request(app).post('/auth/login').send({ username: 'a', password: 'wrong' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'invalid_credentials');
});

test('POST /auth/login returns 400 when fields missing', async () => {
  const app = buildApp({ authService: { register: async () => ({}), login: async () => ({}) } });
  const res = await request(app).post('/auth/login').send({ username: 'only' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});
