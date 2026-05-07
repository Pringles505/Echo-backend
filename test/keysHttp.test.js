const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createKeysRouter } = require('../src/interfaces/http/routes/keys.route');
const {
  BadRequestError,
  NotFoundError,
  RateLimitError,
  UnauthorizedError,
} = require('../src/shared/errors');
const {
  notFoundHandler,
  errorHandler,
} = require('../src/interfaces/http/middleware/errorHandlers');

/**
 * Build an Express app wired with the Keys router. The fake `requireAuth`
 * mirrors the production middleware contract: it sets `req.user.id` from the
 * `x-test-user` header (or denies the request when absent), so the test
 * doesn't need a real JWT layer.
 */
function buildApp({
  keysService,
  mongoConnected = true,
  withAuth = true,
  bundleLimiterRejects = false,
} = {}) {
  const app = express();
  app.use(express.json());

  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };

  const requireAuth = withAuth
    ? (req, res, next) => {
        const userId = req.headers['x-test-user'];
        if (!userId) {
          return res.status(401).json({ success: false, error: 'Unauthorized', code: 'unauthorized' });
        }
        req.user = { id: String(userId) };
        return next();
      }
    : undefined;

  const keyBundleLimiter = bundleLimiterRejects
    ? (_req, res, _next) =>
        res.status(429).json({
          success: false,
          error: 'Too many requests, please try again later',
          code: 'rate_limited',
          retryAfterMs: 60_000,
        })
    : (_req, _res, next) => next();

  app.use(
    createKeysRouter({
      keysService,
      mongoose: fakeMongoose,
      requireAuth,
      keyBundleLimiter,
    })
  );
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function stubService(overrides = {}) {
  return {
    getSignedPreKey: async () => ({ signedPreKey: 'spk', signature: 'sig', spkId: 0 }),
    getIdentityKeyX25519: async () => ({ publicIdentityKeyX25519: 'x25519' }),
    getIdentityKeyEd25519: async () => ({ publicIdentityKeyEd25519: 'ed25519' }),
    getPreKeyBundle: async () => ({
      bundle: {
        publicIdentityKeyX25519: 'x',
        publicIdentityKeyEd25519: 'e',
        signedPreKey: 'spk',
        signature: 'sig',
        spkId: 0,
        opk: { opkId: 'opk-1', opkPub: 'pub' },
      },
    }),
    uploadOneTimePreKeys: async () => ({ stored: 0 }),
    getOpkStatus: async () => ({ currentCount: 0, needed: 100 }),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// /keys/signed-prekey
// ---------------------------------------------------------------------------

test('POST /keys/signed-prekey returns 200 with signed pre-key', async () => {
  const calls = [];
  const app = buildApp({
    keysService: stubService({
      getSignedPreKey: async (input) => {
        calls.push(input);
        return { signedPreKey: 'SPK', signature: 'SIG', spkId: 7 };
      },
    }),
  });

  const res = await request(app)
    .post('/keys/signed-prekey')
    .set('x-test-user', 'U1')
    .send({ targetUserId: 'TARGET' });

  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    success: true,
    signedPreKey: 'SPK',
    signature: 'SIG',
    spkId: 7,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].targetUserId, 'TARGET');
});

test('POST /keys/signed-prekey returns 401 when not authenticated', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app).post('/keys/signed-prekey').send({ targetUserId: 'T1' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /keys/signed-prekey returns 400 when targetUserId missing', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app)
    .post('/keys/signed-prekey')
    .set('x-test-user', 'U1')
    .send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /keys/signed-prekey returns 404 when user not found', async () => {
  const app = buildApp({
    keysService: stubService({
      getSignedPreKey: async () => {
        throw new NotFoundError('User not found', 'user_not_found');
      },
    }),
  });
  const res = await request(app)
    .post('/keys/signed-prekey')
    .set('x-test-user', 'U1')
    .send({ targetUserId: 'GHOST' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

// ---------------------------------------------------------------------------
// /keys/identity/x25519 + /keys/identity/ed25519
// ---------------------------------------------------------------------------

test('POST /keys/identity/x25519 returns 200 with X25519 identity key', async () => {
  const app = buildApp({
    keysService: stubService({
      getIdentityKeyX25519: async () => ({ publicIdentityKeyX25519: 'X-PUB' }),
    }),
  });
  const res = await request(app)
    .post('/keys/identity/x25519')
    .set('x-test-user', 'U1')
    .send({ targetUserId: 'T1' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, publicIdentityKeyX25519: 'X-PUB' });
});

test('POST /keys/identity/ed25519 returns 200 with Ed25519 identity key', async () => {
  const app = buildApp({
    keysService: stubService({
      getIdentityKeyEd25519: async () => ({ publicIdentityKeyEd25519: 'E-PUB' }),
    }),
  });
  const res = await request(app)
    .post('/keys/identity/ed25519')
    .set('x-test-user', 'U1')
    .send({ targetUserId: 'T1' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, publicIdentityKeyEd25519: 'E-PUB' });
});

test('POST /keys/identity/ed25519 returns 404 when user missing', async () => {
  const app = buildApp({
    keysService: stubService({
      getIdentityKeyEd25519: async () => {
        throw new NotFoundError('User not found', 'user_not_found');
      },
    }),
  });
  const res = await request(app)
    .post('/keys/identity/ed25519')
    .set('x-test-user', 'U1')
    .send({ targetUserId: 'GHOST' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

// ---------------------------------------------------------------------------
// /keys/bundle
// ---------------------------------------------------------------------------

test('POST /keys/bundle returns 200 with bundle and forwards requester/ip/UA', async () => {
  let captured = null;
  const app = buildApp({
    keysService: stubService({
      getPreKeyBundle: async (input) => {
        captured = input;
        return {
          bundle: {
            publicIdentityKeyX25519: 'x',
            publicIdentityKeyEd25519: 'e',
            signedPreKey: 'spk',
            signature: 'sig',
            spkId: 0,
            opk: { opkId: 'opk-1', opkPub: 'pub' },
          },
        };
      },
    }),
  });

  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .set('user-agent', 'jest/1.0')
    .send({ targetUserId: 'TARGET' });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.bundle.opk.opkId, 'opk-1');
  assert.ok(captured);
  assert.equal(captured.requesterId, 'REQ1');
  assert.equal(captured.targetUserId, 'TARGET');
  assert.equal(captured.userAgent, 'jest/1.0');
  assert.ok(typeof captured.ip === 'string');
});

test('POST /keys/bundle returns 401 when not authenticated', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app).post('/keys/bundle').send({ targetUserId: 'TARGET' });
  assert.equal(res.status, 401);
});

test('POST /keys/bundle returns 400 when targetUserId missing', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /keys/bundle returns 429 when express rate limiter blocks', async () => {
  const app = buildApp({
    keysService: stubService(),
    bundleLimiterRejects: true,
  });
  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .send({ targetUserId: 'TARGET' });
  assert.equal(res.status, 429);
  assert.equal(res.body.code, 'rate_limited');
});

test('POST /keys/bundle returns 429 when service raises RateLimitError', async () => {
  const app = buildApp({
    keysService: stubService({
      getPreKeyBundle: async () => {
        throw new RateLimitError('Rate limited', 'rate_limited', { retryAfterMs: 30_000 });
      },
    }),
  });
  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .send({ targetUserId: 'TARGET' });
  assert.equal(res.status, 429);
  assert.equal(res.body.code, 'rate_limited');
  assert.deepEqual(res.body.details, { retryAfterMs: 30_000 });
});

test('POST /keys/bundle returns 404 when target user not found', async () => {
  const app = buildApp({
    keysService: stubService({
      getPreKeyBundle: async () => {
        throw new NotFoundError('User not found', 'user_not_found');
      },
    }),
  });
  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .send({ targetUserId: 'GHOST' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'user_not_found');
});

// ---------------------------------------------------------------------------
// /keys/opk/upload
// ---------------------------------------------------------------------------

test('POST /keys/opk/upload returns 200 with stored count (capped happy path)', async () => {
  let captured = null;
  const app = buildApp({
    keysService: stubService({
      uploadOneTimePreKeys: async (input) => {
        captured = input;
        // Simulate cap to remaining capacity: client sent 5, only 3 stored.
        return { stored: 3 };
      },
    }),
  });

  const opks = [
    { opkId: '1', opkPub: 'a' },
    { opkId: '2', opkPub: 'b' },
    { opkId: '3', opkPub: 'c' },
    { opkId: '4', opkPub: 'd' },
    { opkId: '5', opkPub: 'e' },
  ];
  const res = await request(app)
    .post('/keys/opk/upload')
    .set('x-test-user', 'U1')
    .send({ oneTimePreKeys: opks });

  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, stored: 3 });
  assert.equal(captured.userId, 'U1');
  assert.equal(captured.oneTimePreKeys.length, 5);
});

test('POST /keys/opk/upload returns 401 when not authenticated', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app)
    .post('/keys/opk/upload')
    .send({ oneTimePreKeys: [] });
  assert.equal(res.status, 401);
});

test('POST /keys/opk/upload returns 400 when oneTimePreKeys missing', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app)
    .post('/keys/opk/upload')
    .set('x-test-user', 'U1')
    .send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /keys/opk/upload surfaces no_opks_provided as 400', async () => {
  const app = buildApp({
    keysService: stubService({
      uploadOneTimePreKeys: async () => {
        throw new BadRequestError('No OPKs provided', 'no_opks_provided');
      },
    }),
  });
  const res = await request(app)
    .post('/keys/opk/upload')
    .set('x-test-user', 'U1')
    .send({ oneTimePreKeys: [] });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'no_opks_provided');
});

// ---------------------------------------------------------------------------
// /keys/opk/status
// ---------------------------------------------------------------------------

test('GET /keys/opk/status returns 200 with currentCount + needed', async () => {
  const app = buildApp({
    keysService: stubService({
      getOpkStatus: async (input) => {
        assert.equal(input.userId, 'U1');
        return { currentCount: 42, needed: 58 };
      },
    }),
  });
  const res = await request(app).get('/keys/opk/status').set('x-test-user', 'U1');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, currentCount: 42, needed: 58 });
});

test('GET /keys/opk/status returns 401 when not authenticated', async () => {
  const app = buildApp({ keysService: stubService() });
  const res = await request(app).get('/keys/opk/status');
  assert.equal(res.status, 401);
});

test('GET /keys/opk/status returns 503 when DB unavailable', async () => {
  const app = buildApp({ keysService: stubService(), mongoConnected: false });
  const res = await request(app).get('/keys/opk/status').set('x-test-user', 'U1');
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

// ---------------------------------------------------------------------------
// Service-layer UnauthorizedError (e.g. internal getPreKeyBundle requesterId blank)
// ---------------------------------------------------------------------------

test('POST /keys/bundle surfaces service UnauthorizedError as 401', async () => {
  const app = buildApp({
    keysService: stubService({
      getPreKeyBundle: async () => {
        throw new UnauthorizedError('Unauthorized', 'unauthorized');
      },
    }),
  });
  const res = await request(app)
    .post('/keys/bundle')
    .set('x-test-user', 'REQ1')
    .send({ targetUserId: 'TARGET' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});
