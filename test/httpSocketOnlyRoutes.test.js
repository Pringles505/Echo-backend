const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const mongoose = require('mongoose');

const { healthRouter } = require('../src/interfaces/http/routes/health.route');
const { authRouter } = require('../src/interfaces/http/routes/auth.route');
const { messagesRouter } = require('../src/interfaces/http/routes/messages.route');
const { usersRouter } = require('../src/interfaces/http/routes/users.route');
const { contactsRouter } = require('../src/interfaces/http/routes/contacts.route');
const { groupsRouter } = require('../src/interfaces/http/routes/groups.route');
const { callsRouter } = require('../src/interfaces/http/routes/calls.route');
const { keysRouter } = require('../src/interfaces/http/routes/keys.route');

const SOCKET_ONLY_ENDPOINTS = [
  ['POST', '/auth/register'],
  ['POST', '/auth/login'],
  ['POST', '/messages/check'],
  ['POST', '/messages/latest-number'],
  ['POST', '/messages/mark-seen'],
  ['POST', '/users/search'],
  ['GET', '/users/U1'],
  ['PUT', '/users/profile/update'],
  ['GET', '/users/online'],
  ['DELETE', '/users/account/delete'],
  ['POST', '/contacts/add-friend'],
  ['POST', '/contacts/remove-friend'],
  ['POST', '/groups/create'],
  ['GET', '/groups/list'],
  ['GET', '/groups/G1'],
  ['POST', '/groups/G1/add-member'],
  ['POST', '/groups/G1/remove-member'],
  ['POST', '/calls/initiate'],
  ['POST', '/calls/accept'],
  ['POST', '/calls/decline'],
  ['POST', '/calls/end'],
  ['POST', '/calls/media-state'],
  ['POST', '/keys/signed-prekey'],
  ['POST', '/keys/identity/x25519'],
  ['POST', '/keys/identity/ed25519'],
  ['POST', '/keys/bundle'],
  ['POST', '/keys/opk/upload'],
  ['GET', '/keys/opk/status'],
];

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use(healthRouter);
  app.use(authRouter);
  app.use(messagesRouter);
  app.use(usersRouter);
  app.use(contactsRouter);
  app.use(groupsRouter);
  app.use(callsRouter);
  app.use(keysRouter);
  return app;
}

async function runRequest(baseUrl, method, path) {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify({ sample: true }),
  });
  const data = await response.json();
  return { status: response.status, data };
}

test('socket-only HTTP endpoints return 503 when DB is unavailable', async () => {
  const app = makeApp();
  const originalReadyState = mongoose.connection.readyState;
  mongoose.connection.readyState = 0;

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    for (const [method, path] of SOCKET_ONLY_ENDPOINTS) {
      const { status, data } = await runRequest(baseUrl, method, path);
      assert.equal(status, 503, `${method} ${path} should return 503`);
      assert.deepEqual(data, {
        success: false,
        error: 'Database connection is not available',
      });
    }
  } finally {
    mongoose.connection.readyState = originalReadyState;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('socket-only HTTP endpoints return 501 when DB is available', async () => {
  const app = makeApp();
  const originalReadyState = mongoose.connection.readyState;
  mongoose.connection.readyState = 1;

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    for (const [method, path] of SOCKET_ONLY_ENDPOINTS) {
      const { status, data } = await runRequest(baseUrl, method, path);
      assert.equal(status, 501, `${method} ${path} should return 501`);
      assert.deepEqual(data, {
        success: false,
        error: 'This endpoint is only available via Socket.IO',
      });
    }
  } finally {
    mongoose.connection.readyState = originalReadyState;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('health endpoint stays healthy without DB', async () => {
  const app = makeApp();
  const originalReadyState = mongoose.connection.readyState;
  mongoose.connection.readyState = 0;

  const server = app.listen(0);
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(response.status, 200);
  } finally {
    mongoose.connection.readyState = originalReadyState;
    await new Promise((resolve) => server.close(resolve));
  }
});
