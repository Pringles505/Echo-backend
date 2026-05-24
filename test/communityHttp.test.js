const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createCommunityRouter } = require('../src/interfaces/http/routes/community.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
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

function buildApp({ eventsService, newsletterService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });

  const router = createCommunityRouter({
    eventsService,
    newsletterService,
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

function makeEventsService(overrides = {}) {
  return {
    listActiveEvents: async () => ({ events: [], page: 1, limit: 20, total: 0 }),
    registerForEvent: async () => ({ registered: true, eventId: 'E1', userId: 'U1' }),
    createEvent: async () => ({ eventId: 'E1' }),
    ...overrides,
  };
}

function makeNewsletterService(overrides = {}) {
  return {
    subscribe: async () => ({ email: 'a@b.com', status: 'active', subscribedAt: new Date() }),
    ...overrides,
  };
}

test('GET /community/events returns 200 with events list (public, no token)', async () => {
  const captured = [];
  const events = makeEventsService({
    listActiveEvents: async (q) => {
      captured.push(q);
      return {
        events: [{ eventId: 'E1', title: 'Hack' }],
        page: 1, limit: 20, total: 1,
      };
    },
  });
  const app = buildApp({ eventsService: events, newsletterService: makeNewsletterService() });
  const res = await request(app).get('/community/events?type=hackathon&page=2&limit=5');
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.events.length, 1);
  assert.equal(captured[0].type, 'hackathon');
  assert.equal(captured[0].page, '2');
});

test('GET /community/events 503 when DB unavailable', async () => {
  const app = buildApp({
    eventsService: makeEventsService(),
    newsletterService: makeNewsletterService(),
    mongoConnected: false,
  });
  const res = await request(app).get('/community/events');
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

test('POST /community/events/:eventId/register 200 on success', async () => {
  const seen = [];
  const events = makeEventsService({
    registerForEvent: async (input) => {
      seen.push(input);
      return { registered: true, eventId: input.eventId, userId: input.userId };
    },
  });
  const app = buildApp({ eventsService: events, newsletterService: makeNewsletterService() });
  const res = await authed(request(app).post('/community/events/E1/register'));
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.registered, true);
  assert.deepEqual(seen[0], { eventId: 'E1', userId: 'U1' });
});

test('POST /community/events/:eventId/register 401 without token', async () => {
  const app = buildApp({
    eventsService: makeEventsService(),
    newsletterService: makeNewsletterService(),
  });
  const res = await request(app).post('/community/events/E1/register');
  assert.equal(res.status, 401);
});

test('POST /community/events/:eventId/register 404 when event missing', async () => {
  const events = makeEventsService({
    registerForEvent: async () => { throw new NotFoundError('Event not found', 'event_not_found'); },
  });
  const app = buildApp({ eventsService: events, newsletterService: makeNewsletterService() });
  const res = await authed(request(app).post('/community/events/EX/register'));
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'event_not_found');
});

test('POST /community/events/:eventId/register 409 on duplicate', async () => {
  const events = makeEventsService({
    registerForEvent: async () => { throw new ConflictError('Already registered', 'already_registered'); },
  });
  const app = buildApp({ eventsService: events, newsletterService: makeNewsletterService() });
  const res = await authed(request(app).post('/community/events/E1/register'));
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'already_registered');
});

test('POST /community/subscribe 200 with normalized email', async () => {
  const seen = [];
  const newsletter = makeNewsletterService({
    subscribe: async (input) => {
      seen.push(input);
      return { email: input.email, status: 'active', subscribedAt: new Date() };
    },
  });
  const app = buildApp({ eventsService: makeEventsService(), newsletterService: newsletter });
  const res = await request(app)
    .post('/community/subscribe')
    .send({ email: 'foo@bar.com', source: 'sealed-mail' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.subscriber.email, 'foo@bar.com');
  assert.equal(seen[0].source, 'sealed-mail');
});

test('POST /community/subscribe 400 when email missing', async () => {
  const app = buildApp({
    eventsService: makeEventsService(),
    newsletterService: makeNewsletterService(),
  });
  const res = await request(app).post('/community/subscribe').send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /community/subscribe 400 when email invalid', async () => {
  const newsletter = makeNewsletterService({
    subscribe: async () => { throw new BadRequestError('A valid email is required', 'validation_error'); },
  });
  const app = buildApp({ eventsService: makeEventsService(), newsletterService: newsletter });
  const res = await request(app).post('/community/subscribe').send({ email: 'notanemail' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});
