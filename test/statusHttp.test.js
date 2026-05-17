const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createStatusRouter } = require('../src/interfaces/http/routes/status.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({ statusService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  const router = createStatusRouter({ statusService, mongoose: fakeMongoose });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

test('GET /status/services 200 with snapshot', async () => {
  const svc = {
    getServicesStatus: async () => ({
      overall: 'ok',
      uptime: 42,
      timestamp: '2026-05-17T00:00:00Z',
      services: [
        { name: 'mongodb', status: 'up', latencyMs: 5 },
        { name: 'socket.io', status: 'up', connections: 3 },
      ],
    }),
  };
  const app = buildApp({ statusService: svc });
  const res = await request(app).get('/status/services');
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.overall, 'ok');
  assert.equal(res.body.services.length, 2);
  assert.equal(res.body.services[0].name, 'mongodb');
});

test('GET /status/services 200 reports degraded when a service is down', async () => {
  const svc = {
    getServicesStatus: async () => ({
      overall: 'degraded',
      uptime: 1,
      timestamp: '2026-05-17T00:00:00Z',
      services: [{ name: 'mongodb', status: 'down', latencyMs: null }],
    }),
  };
  const app = buildApp({ statusService: svc });
  const res = await request(app).get('/status/services');
  assert.equal(res.status, 200);
  assert.equal(res.body.overall, 'degraded');
  assert.equal(res.body.services[0].status, 'down');
});

test('GET /status/services no auth required (public)', async () => {
  const svc = {
    getServicesStatus: async () => ({ overall: 'ok', uptime: 0, timestamp: '', services: [] }),
  };
  const app = buildApp({ statusService: svc });
  const res = await request(app).get('/status/services');
  assert.equal(res.status, 200);
});
