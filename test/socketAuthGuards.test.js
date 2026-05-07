const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');

const dotenv = require('dotenv');
const envTestPath = path.join(__dirname, '..', '.env.test');
const envPath = path.join(__dirname, '..', '.env');
dotenv.config({ path: fs.existsSync(envTestPath) ? envTestPath : envPath });

if (process.env.MONGO_URI_TEST) {
  process.env.MONGO_URI = process.env.MONGO_URI_TEST;
}
if (!process.env.MONGO_URI && process.env.MONGO_URI_SECRET) {
  process.env.MONGO_URI = process.env.MONGO_URI_SECRET;
}
if (!process.env.MONGO_URI) {
  throw new Error(
    'Missing MONGO_URI. Set MONGO_URI_TEST (recommended), MONGO_URI, or MONGO_URI_SECRET before running tests.'
  );
}
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

const ioClient = require('socket.io-client');
const { server, mongoose } = require('../server');

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, 'connected');
}

function emitAck(client, event, payload) {
  return new Promise((resolve) => {
    client.emit(event, payload, (ack) => resolve(ack));
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test('unauthorized socket events are explicitly rejected with stable code', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  let client = null;
  try {
    client = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      auth: {},
    });
    await once(client, 'connect');

    const protectedAck = await emitAck(client, 'getOnlineUsers', {});
    assert.equal(protectedAck?.success, false);
    assert.equal(protectedAck?.error, 'unauthorized');
  } finally {
    if (client) client.disconnect();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('public auth events return validation errors and do not require callback', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  let client = null;
  try {
    client = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      auth: {},
    });
    await once(client, 'connect');

    const loginAck = await emitAck(client, 'login', { username: 'u-only' });
    assert.equal(loginAck?.success, false);
    assert.ok(typeof loginAck?.error === 'string', 'login returns string error');

    const registerAck = await emitAck(client, 'register', {
      username: 'user-no-keybundle',
      password: 'pass',
    });
    assert.equal(registerAck?.success, false);
    assert.ok(typeof registerAck?.error === 'string', 'register returns string error');

    client.emit('login', { username: 'without-callback' });
    await sleep(100);
    assert.equal(client.connected, true);
  } finally {
    if (client) client.disconnect();
    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
});
