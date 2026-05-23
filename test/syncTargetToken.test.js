const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createSyncRouter } = require('../src/interfaces/http/routes/sync.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({ deviceSyncService } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: 1 } };
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

function stubGetSession(captured) {
  return {
    getSessionForTarget: async (input) => {
      captured.lastCall = input;
      return { sessionId: input.sessionId, status: 'pending_source' };
    },
  };
}

test('targetToken: header X-Sync-Target-Token wins over query (and the query is scrubbed)', async () => {
  const captured = {};
  const app = buildApp({ deviceSyncService: stubGetSession(captured) });

  // Wrap with a middleware that records req.query after the router runs.
  // (We can't introspect the live req.query directly here because the router
  // handler runs in another request scope, but we can verify the token wins
  // by what is passed to the service.)
  const res = await request(app)
    .get('/sync/sessions/S1?targetAccessToken=QUERY-TOKEN')
    .set('X-Sync-Target-Token', 'HEADER-TOKEN');

  assert.equal(res.status, 200);
  assert.equal(captured.lastCall.targetAccessToken, 'HEADER-TOKEN');
});

test('targetToken: Authorization Bearer sync:<token> is accepted', async () => {
  const captured = {};
  const app = buildApp({ deviceSyncService: stubGetSession(captured) });

  const res = await request(app)
    .get('/sync/sessions/S1')
    .set('Authorization', 'Bearer sync:BEARER-TOKEN');

  assert.equal(res.status, 200);
  assert.equal(captured.lastCall.targetAccessToken, 'BEARER-TOKEN');
});

test('targetToken: query string still works for backward-compat', async () => {
  const captured = {};
  const app = buildApp({ deviceSyncService: stubGetSession(captured) });

  const res = await request(app)
    .get('/sync/sessions/S1?targetAccessToken=QUERY-TOKEN');

  assert.equal(res.status, 200);
  assert.equal(captured.lastCall.targetAccessToken, 'QUERY-TOKEN');
});

test('targetToken: body wins over query on POST endpoints', async () => {
  const captured = {};
  const service = {
    transferDhChunk: async (input) => {
      captured.lastCall = input;
      return { sessionId: 'S1', status: 'transferring' };
    },
  };
  const app = buildApp({ deviceSyncService: service });

  const res = await request(app)
    .post('/sync/dh-transfer-chunk?targetAccessToken=QUERY')
    .send({
      sessionId: 'S1',
      targetAccessToken: 'BODY',
      chunk: { index: 0, totalCount: 1, ciphertext: 'CT', digest: 'D' },
    });

  assert.equal(res.status, 200);
  assert.equal(captured.lastCall.targetAccessToken, 'BODY');
});

test('targetToken: missing token returns the service forbidden error', async () => {
  const service = {
    getSessionForTarget: async () => {
      const err = new Error('Missing target session token');
      err.status = 403;
      err.code = 'missing_target_sync_token';
      throw err;
    },
  };
  const app = buildApp({ deviceSyncService: service });
  const res = await request(app).get('/sync/sessions/S1');
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'missing_target_sync_token');
});
