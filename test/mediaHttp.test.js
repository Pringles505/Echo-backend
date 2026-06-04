const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');
const { Readable } = require('node:stream');
const fs = require('node:fs/promises');

const { createMediaRouter } = require('../src/interfaces/http/routes/media.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const mediaStorage = require('../src/interfaces/socket/context/mediaStorage');

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

// In-memory stub so the route tests don't touch the filesystem.
function makeStubStorage() {
  const store = new Map();
  let n = 0;
  return {
    store,
    saveMediaBlob: async (bytes) => {
      const id = `blob${(n += 1)}`;
      store.set(id, Buffer.from(bytes));
      return id;
    },
    openMediaBlobStream: async (id) => {
      if (!store.has(id)) return null;
      const buf = store.get(id);
      return { stream: Readable.from(buf), size: buf.length };
    },
  };
}

function buildApp({ storage, maxSize } = {}) {
  const app = express();
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });
  app.use(createMediaRouter({ requireAuth, mediaStorage: storage, maxSize }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function binaryParser(res, cb) {
  res.setEncoding('binary');
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => cb(null, Buffer.from(data, 'binary')));
}

test('POST /media rejects unauthenticated upload', async () => {
  const app = buildApp({ storage: makeStubStorage() });
  const res = await request(app)
    .post('/media')
    .set('Content-Type', 'application/octet-stream')
    .send(Buffer.from([1, 2, 3]));
  assert.equal(res.status, 401);
});

test('POST /media stores a blob and GET returns the exact bytes', async () => {
  const storage = makeStubStorage();
  const app = buildApp({ storage });
  const payload = Buffer.from([0, 1, 2, 250, 251, 255, 7, 7]);

  const post = await request(app)
    .post('/media')
    .set('Authorization', `Bearer ${VALID_TOKEN}`)
    .set('Content-Type', 'application/octet-stream')
    .send(payload);
  assert.equal(post.status, 200);
  assert.equal(post.body.success, true);
  assert.ok(post.body.mediaId);

  const get = await request(app)
    .get(`/media/${post.body.mediaId}`)
    .set('Authorization', `Bearer ${VALID_TOKEN}`)
    .buffer(true)
    .parse(binaryParser);
  assert.equal(get.status, 200);
  assert.equal(get.headers['content-type'], 'application/octet-stream');
  assert.ok(Buffer.isBuffer(get.body));
  assert.deepEqual(get.body, payload);
});

test('GET /media/:id returns 404 for an unknown blob', async () => {
  const app = buildApp({ storage: makeStubStorage() });
  const res = await request(app)
    .get('/media/doesnotexist')
    .set('Authorization', `Bearer ${VALID_TOKEN}`);
  assert.equal(res.status, 404);
});

test('POST /media enforces the size cap (413)', async () => {
  const app = buildApp({ storage: makeStubStorage(), maxSize: 8 });
  const res = await request(app)
    .post('/media')
    .set('Authorization', `Bearer ${VALID_TOKEN}`)
    .set('Content-Type', 'application/octet-stream')
    .send(Buffer.alloc(64, 1));
  assert.equal(res.status, 413);
  assert.equal(res.body.code, 'media_too_large');
});

test('mediaStorage persists and reads back the exact ciphertext', async () => {
  const payload = Buffer.from([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 200, 255]);
  const mediaId = await mediaStorage.saveMediaBlob(payload);
  assert.ok(mediaStorage.isValidMediaId(mediaId));
  try {
    const opened = await mediaStorage.openMediaBlobStream(mediaId);
    assert.ok(opened);
    assert.equal(opened.size, payload.length);
    const chunks = [];
    for await (const c of opened.stream) chunks.push(c);
    assert.deepEqual(Buffer.concat(chunks), payload);
  } finally {
    const p = await mediaStorage.resolveMediaBlobPath(mediaId);
    if (p) await fs.unlink(p).catch(() => {});
  }
});

test('mediaStorage rejects traversal / malformed ids', async () => {
  assert.equal(await mediaStorage.resolveMediaBlobPath('../secret'), null);
  assert.equal(await mediaStorage.openMediaBlobStream('a/b'), null);
  assert.equal(mediaStorage.isValidMediaId('../x'), false);
});
