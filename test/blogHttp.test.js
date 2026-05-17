const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createBlogRouter } = require('../src/interfaces/http/routes/blog.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const { NotFoundError } = require('../src/shared/errors');

function buildApp({ blogService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  const router = createBlogRouter({ blogService, mongoose: fakeMongoose });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

test('GET /blog/posts/:slug 200 when published post exists', async () => {
  const seen = [];
  const blog = {
    getPostBySlug: async ({ slug }) => {
      seen.push(slug);
      return { slug, title: 'Hello', content: 'World' };
    },
  };
  const app = buildApp({ blogService: blog });
  const res = await request(app).get('/blog/posts/hello-world');
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.post.title, 'Hello');
  assert.equal(seen[0], 'hello-world');
});

test('GET /blog/posts/:slug 404 when post missing or unpublished', async () => {
  const blog = {
    getPostBySlug: async () => { throw new NotFoundError('Post not found', 'post_not_found'); },
  };
  const app = buildApp({ blogService: blog });
  const res = await request(app).get('/blog/posts/nope');
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'post_not_found');
});

test('GET /blog/posts/:slug 503 when DB unavailable', async () => {
  const blog = { getPostBySlug: async () => ({}) };
  const app = buildApp({ blogService: blog, mongoConnected: false });
  const res = await request(app).get('/blog/posts/any');
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});
