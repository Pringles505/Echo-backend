const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createAdminRouter } = require('../src/interfaces/http/routes/admin.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const { NotFoundError, ConflictError } = require('../src/shared/errors');

const ADMIN_TOKEN = 'admin-token';
const USER_TOKEN = 'user-token';
const ADMIN_USER = { id: 'A1', username: 'admin', role: 'admin' };
const NORMAL_USER = { id: 'U1', username: 'alice', role: 'user' };

function makeJwtMock() {
  return {
    verify(token, _secret, cb) {
      if (token === ADMIN_TOKEN) return cb(null, ADMIN_USER);
      if (token === USER_TOKEN) return cb(null, NORMAL_USER);
      return cb(new Error('invalid'));
    },
  };
}

function makeUserModel(roleByUserId = {}) {
  return {
    findOne(filter) {
      const user = roleByUserId[filter.id];
      return {
        lean: async () => (user ? { role: user.role } : null),
      };
    },
  };
}

function buildApp({ blogService, eventsService, mongoConnected = true, userRoles } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const User = makeUserModel(
    userRoles || { A1: { role: 'admin' }, U1: { role: 'user' } }
  );
  const { requireAdmin } = createAuthMiddleware({ jwt: makeJwtMock(), User });

  const router = createAdminRouter({
    blogService,
    eventsService,
    mongoose: fakeMongoose,
    requireAdmin,
  });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function authed(req, token = ADMIN_TOKEN) {
  return req.set('Authorization', `Bearer ${token}`);
}

function makeBlogService(overrides = {}) {
  return {
    createPost: async (input) => ({
      slug: 'hello', title: input.title, content: input.content, status: 'draft',
    }),
    updatePost: async (input) => ({ slug: 'hello', status: input.changes.status || 'draft' }),
    ...overrides,
  };
}

function makeEventsService(overrides = {}) {
  return {
    createEvent: async (input) => ({ eventId: 'E1', title: input.title, status: 'draft' }),
    ...overrides,
  };
}

// ---------------------------------------- POST /admin/blog

test('POST /admin/blog 201 when admin creates post', async () => {
  const seen = [];
  const blog = makeBlogService({
    createPost: async (input) => {
      seen.push(input);
      return { slug: 'hello-world', title: input.title, content: input.content, status: 'draft' };
    },
  });
  const app = buildApp({ blogService: blog, eventsService: makeEventsService() });
  const res = await authed(request(app).post('/admin/blog'))
    .send({ title: 'Hello World', content: 'Body' });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.post.title, 'Hello World');
  assert.equal(seen[0].authorId, 'A1');
});

test('POST /admin/blog 403 when non-admin user', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await authed(request(app).post('/admin/blog'), USER_TOKEN)
    .send({ title: 'X', content: 'Y' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden_admin_required');
});

test('POST /admin/blog 401 without token', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await request(app).post('/admin/blog').send({ title: 'X', content: 'Y' });
  assert.equal(res.status, 401);
});

test('POST /admin/blog 400 when title missing', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await authed(request(app).post('/admin/blog')).send({ content: 'Y' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /admin/blog 409 on slug conflict from service', async () => {
  const blog = makeBlogService({
    createPost: async () => { throw new ConflictError('Slug already exists', 'slug_conflict'); },
  });
  const app = buildApp({ blogService: blog, eventsService: makeEventsService() });
  const res = await authed(request(app).post('/admin/blog')).send({ title: 'X', content: 'Y' });
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'slug_conflict');
});

// ---------------------------------------- PATCH /admin/blog/:id

test('PATCH /admin/blog/:id 200 on update', async () => {
  const seen = [];
  const blog = makeBlogService({
    updatePost: async (input) => {
      seen.push(input);
      return { slug: 'hello', status: input.changes.status };
    },
  });
  const app = buildApp({ blogService: blog, eventsService: makeEventsService() });
  const res = await authed(request(app).patch('/admin/blog/507f1f77bcf86cd799439011'))
    .send({ status: 'published' });
  assert.equal(res.status, 200);
  assert.equal(res.body.post.status, 'published');
  assert.equal(seen[0].id, '507f1f77bcf86cd799439011');
});

test('PATCH /admin/blog/:id 404 when post missing', async () => {
  const blog = makeBlogService({
    updatePost: async () => { throw new NotFoundError('Post not found', 'post_not_found'); },
  });
  const app = buildApp({ blogService: blog, eventsService: makeEventsService() });
  const res = await authed(request(app).patch('/admin/blog/abc')).send({ title: 'New' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'post_not_found');
});

test('PATCH /admin/blog/:id 403 when non-admin', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await authed(request(app).patch('/admin/blog/abc'), USER_TOKEN)
    .send({ title: 'X' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden_admin_required');
});

// ---------------------------------------- POST /admin/events

test('POST /admin/events 201 when admin creates event', async () => {
  const seen = [];
  const events = makeEventsService({
    createEvent: async (input) => {
      seen.push(input);
      return { eventId: 'EVT1', title: input.title, status: 'active' };
    },
  });
  const app = buildApp({ blogService: makeBlogService(), eventsService: events });
  const res = await authed(request(app).post('/admin/events')).send({
    title: 'Hackathon 2026',
    startsAt: '2026-06-01T10:00:00Z',
    eventType: 'hackathon',
    capacity: 100,
    status: 'active',
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.event.eventId, 'EVT1');
  assert.equal(seen[0].createdBy, 'A1');
  assert.equal(seen[0].eventType, 'hackathon');
});

test('POST /admin/events 400 when startsAt missing', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await authed(request(app).post('/admin/events')).send({ title: 'X' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /admin/events 403 when non-admin', async () => {
  const app = buildApp({
    blogService: makeBlogService(),
    eventsService: makeEventsService(),
  });
  const res = await authed(request(app).post('/admin/events'), USER_TOKEN)
    .send({ title: 'X', startsAt: '2026-01-01' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden_admin_required');
});
