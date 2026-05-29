const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createSyncRouter } = require('../src/interfaces/http/routes/sync.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({ deviceSyncService, mongoConnected = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized', code: 'unauthorized' });
    }
    req.user = { id: 'U1', username: 'alice' };
    return next();
  };
  app.use(createSyncRouter({ deviceSyncService, mongoose: fakeMongoose, requireAuth }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

test('POST /sync/create-session is public and returns the rendezvous payload', async () => {
  const calls = [];
  const service = {
    createSession: async (input) => {
      calls.push(input);
      return { sessionId: 'S1', sessionCode: '123456', expiresAt: '2026-05-15T12:00:00.000Z', targetAccessToken: 'tok', status: 'pending_source' };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const res = await request(app).post('/sync/create-session').send({ targetEphemeralPubKey: 'pub' });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.sessionId, 'S1');
  assert.equal(calls[0].targetEphemeralPubKey, 'pub');
});

test('POST /sync/attach-source requires bearer auth and forwards the source user', async () => {
  let captured = null;
  const service = {
    attachSource: async (input) => {
      captured = input;
      return { sessionId: 'S1', status: 'awaiting_confirmation' };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const unauthorized = await request(app).post('/sync/attach-source').send({ sessionId: 'S1', sourceEphemeralPubKey: 'pub' });
  assert.equal(unauthorized.status, 401);

  const res = await request(app)
    .post('/sync/attach-source')
    .set('Authorization', 'Bearer token')
    .send({ sessionId: 'S1', sourceEphemeralPubKey: 'pub' });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(captured.sourceUserId, 'U1');
});

test('GET /sync/sessions/:sessionId forwards the target session token header', async () => {
  let captured = null;
  const service = {
    getSessionForTarget: async (input) => {
      captured = input;
      return { sessionId: 'S1', status: 'pending_source' };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const res = await request(app)
    .get('/sync/sessions/S1')
    .set('X-Sync-Target-Token', 'target-token');

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(captured.sessionId, 'S1');
  assert.equal(captured.targetAccessToken, 'target-token');
});

test('GET /sync/dh-session/:sessionId forwards the target session token header', async () => {
  let captured = null;
  const service = {
    getDhSession: async (input) => {
      captured = input;
      return { sessionId: 'S1', status: 'completed', sourceEphemeralPubKey: 'scanner-pub' };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const res = await request(app)
    .get('/sync/dh-session/S1')
    .set('X-Sync-Target-Token', 'target-token');

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.session.status, 'completed');
  assert.equal(captured.sessionId, 'S1');
  assert.equal(captured.targetAccessToken, 'target-token');
});

test('POST /sync/dh-transfer-chunk is public with target token and forwards chunk', async () => {
  let captured = null;
  const service = {
    transferDhChunk: async (input) => {
      captured = input;
      return { sessionId: 'S1', status: 'transferring', totalChunkCount: 1 };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const chunk = {
    index: 0,
    totalCount: 1,
    ciphertext: 'abc',
    nonce: 'nonce',
    digest: 'digest',
  };
  const res = await request(app)
    .post('/sync/dh-transfer-chunk')
    .send({ sessionId: 'S1', targetAccessToken: 'target-token', chunk });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.deepEqual(captured, { sessionId: 'S1', targetAccessToken: 'target-token', chunk });
});
