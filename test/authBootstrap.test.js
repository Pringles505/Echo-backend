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
const { server, mongoose, User } = require('../server');

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, 'connected');
}

function emitAck(client, event, payload) {
  return new Promise((resolve) => {
    client.emit(event, payload, (ack) => resolve(ack));
  });
}

test('register/login works from empty state with valid key bundle', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts = Date.now();
  const username = `auth_user_${ts}`;
  const password = 's3cure-pass';

  let client = null;
  try {
    client = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
    });
    await once(client, 'connect');

    const registerAck = await emitAck(client, 'register', {
      username,
      password,
      keyBundle: {
        publicIdentityKeyX25519: 'identity-x25519',
        publicIdentityKeyEd25519: 'identity-ed25519',
        publicSignedPreKey: ['signed-pre-key', 'signed-pre-key-signature'],
        oneTimePreKeys: [{ opkId: 'opk-1', publicKey: 'opk-public-key' }],
      },
      aboutme: 'new user',
    });

    assert.equal(registerAck?.success, true);
    assert.ok(registerAck?.userId);

    const loginAck = await emitAck(client, 'login', {
      username,
      password,
    });

    assert.equal(loginAck?.success, true);
    assert.ok(loginAck?.token);
    assert.equal(loginAck?.userId, registerAck.userId);

    const savedUser = await User.findOne({ id: registerAck.userId }).lean();
    assert.ok(savedUser);
    assert.equal(savedUser.username, username);
  } finally {
    if (client) client.disconnect();
    await User.deleteMany({ username });
    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
});
