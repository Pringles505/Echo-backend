const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createEnvelopesRouter } = require('../src/interfaces/http/routes/envelopes.route');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({ deviceManagementService, jwtUser = { id: 'U1', deviceId: 'D1', deviceUserId: 'alice_x1' } } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: 1 } };
  const requireAuth = (req, res, next) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Unauthorized', code: 'unauthorized' });
    }
    req.user = jwtUser;
    return next();
  };
  app.use(createEnvelopesRouter({ deviceManagementService, mongoose: fakeMongoose, requireAuth }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

const okService = (capture = {}) => ({
  storeEnvelopes: async (input) => {
    capture.store = input;
    return { stored: input.envelopes.length };
  },
  fetchEnvelopes: async (input) => {
    capture.fetch = input;
    return [];
  },
  ackEnvelope: async (input) => {
    capture.ack = input;
    return { envelopeId: input.envelopeId, status: input.status };
  },
});

test('POST /messages/envelopes accepts a valid batch and forwards sender identity', async () => {
  const capture = {};
  const app = buildApp({ deviceManagementService: okService(capture) });

  const res = await request(app)
    .post('/messages/envelopes')
    .set('Authorization', 'Bearer dummy')
    .send({
      senderDeviceId: 'D1',
      envelopes: [
        { recipientDeviceId: 'D2', ciphertext: 'CT', nonce: 'N', conversationId: 'C1' },
      ],
    });

  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.stored, 1);
  assert.equal(capture.store.senderDeviceId, 'D1');
  assert.equal(capture.store.logicalSenderId, 'U1');
});

test('POST /messages/envelopes rejects when senderDeviceId does not match the JWT', async () => {
  const app = buildApp({ deviceManagementService: okService() });

  const res = await request(app)
    .post('/messages/envelopes')
    .set('Authorization', 'Bearer dummy')
    .send({
      senderDeviceId: 'D-spoof',
      envelopes: [{ recipientDeviceId: 'D2', ciphertext: 'CT' }],
    });

  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'envelope_sender_mismatch');
});

test('POST /messages/envelopes accepts the synthetic deviceUserId as senderDeviceId', async () => {
  const capture = {};
  const app = buildApp({ deviceManagementService: okService(capture) });

  const res = await request(app)
    .post('/messages/envelopes')
    .set('Authorization', 'Bearer dummy')
    .send({
      senderDeviceId: 'alice_x1',
      envelopes: [{ recipientDeviceId: 'D2', ciphertext: 'CT' }],
    });

  assert.equal(res.status, 201);
  assert.equal(capture.store.senderDeviceId, 'alice_x1');
});

test('POST /messages/envelopes rejects entries without ciphertext (plaintext defense)', async () => {
  const app = buildApp({ deviceManagementService: okService() });

  const res = await request(app)
    .post('/messages/envelopes')
    .set('Authorization', 'Bearer dummy')
    .send({
      senderDeviceId: 'D1',
      envelopes: [{ recipientDeviceId: 'D2' }],
    });

  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/envelopes rejects empty arrays', async () => {
  const app = buildApp({ deviceManagementService: okService() });

  const res = await request(app)
    .post('/messages/envelopes')
    .set('Authorization', 'Bearer dummy')
    .send({ senderDeviceId: 'D1', envelopes: [] });

  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /messages/envelopes 401 without bearer token', async () => {
  const app = buildApp({ deviceManagementService: okService() });

  const res = await request(app)
    .post('/messages/envelopes')
    .send({ senderDeviceId: 'D1', envelopes: [{ recipientDeviceId: 'D2', ciphertext: 'CT' }] });

  assert.equal(res.status, 401);
});

test('GET /messages/envelopes/:deviceId allows only the owning device', async () => {
  const capture = {};
  const app = buildApp({ deviceManagementService: okService(capture) });

  const allowed = await request(app)
    .get('/messages/envelopes/D1')
    .set('Authorization', 'Bearer dummy');
  assert.equal(allowed.status, 200);
  assert.equal(capture.fetch.deviceId, 'D1');

  const forbidden = await request(app)
    .get('/messages/envelopes/D-other')
    .set('Authorization', 'Bearer dummy');
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.body.code, 'envelope_forbidden');
});

test('GET /messages/envelopes/:deviceId also accepts the deviceUserId', async () => {
  const capture = {};
  const app = buildApp({ deviceManagementService: okService(capture) });

  const res = await request(app)
    .get('/messages/envelopes/alice_x1')
    .set('Authorization', 'Bearer dummy');

  assert.equal(res.status, 200);
  assert.equal(capture.fetch.deviceId, 'alice_x1');
});

test('POST /messages/envelopes/:envelopeId/ack: device guard mirrors the GET', async () => {
  const capture = {};
  const app = buildApp({ deviceManagementService: okService(capture) });

  const ok = await request(app)
    .post('/messages/envelopes/E1/ack')
    .set('Authorization', 'Bearer dummy')
    .send({ deviceId: 'D1', status: 'read' });
  assert.equal(ok.status, 200);
  assert.equal(capture.ack.envelopeId, 'E1');
  assert.equal(capture.ack.status, 'read');

  const bad = await request(app)
    .post('/messages/envelopes/E1/ack')
    .set('Authorization', 'Bearer dummy')
    .send({ deviceId: 'D-other' });
  assert.equal(bad.status, 403);
  assert.equal(bad.body.code, 'envelope_forbidden');
});
