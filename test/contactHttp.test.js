const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createContactRouter } = require('../src/interfaces/http/routes/contact.route');
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

function buildApp({ supportService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { optionalAuth } = createAuthMiddleware({ jwt: makeJwtMock() });

  const router = createContactRouter({
    supportService,
    mongoose: fakeMongoose,
    optionalAuth,
  });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

test('POST /contact/submit 201 with anonymous submission', async () => {
  const seen = [];
  const svc = {
    submitTicket: async (input) => {
      seen.push(input);
      return { ticketId: 'TKT1234567', status: 'open', createdAt: new Date() };
    },
  };
  const app = buildApp({ supportService: svc });
  const res = await request(app).post('/contact/submit').send({
    name: 'John',
    email: 'john@example.com',
    subject: 'Help',
    message: 'Need help with login',
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.ticket.ticketId, 'TKT1234567');
  assert.equal(seen[0].userId, null);
  assert.equal(seen[0].name, 'John');
});

test('POST /contact/submit 201 with authenticated user attaches userId', async () => {
  const seen = [];
  const svc = {
    submitTicket: async (input) => {
      seen.push(input);
      return { ticketId: 'T1', status: 'open', createdAt: new Date() };
    },
  };
  const app = buildApp({ supportService: svc });
  const res = await request(app)
    .post('/contact/submit')
    .set('Authorization', `Bearer ${VALID_TOKEN}`)
    .send({
      name: 'Alice',
      email: 'alice@example.com',
      subject: 'Account issue',
      message: 'Cannot log in',
      category: 'account',
    });
  assert.equal(res.status, 201);
  assert.equal(seen[0].userId, 'U1');
  assert.equal(seen[0].category, 'account');
});

test('POST /contact/submit 400 when message missing', async () => {
  const app = buildApp({ supportService: { submitTicket: async () => ({}) } });
  const res = await request(app).post('/contact/submit').send({
    name: 'X',
    email: 'x@y.com',
    subject: 'S',
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /contact/submit 400 when email invalid', async () => {
  const svc = {
    submitTicket: async () => { throw new BadRequestError('A valid email is required', 'validation_error'); },
  };
  const app = buildApp({ supportService: svc });
  const res = await request(app).post('/contact/submit').send({
    name: 'X',
    email: 'notanemail',
    subject: 'S',
    message: 'M',
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});
