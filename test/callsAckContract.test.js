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

const jwt = require('jsonwebtoken');
const ioClient = require('socket.io-client');
const { server, mongoose, User, Call } = require('../server');

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, 'connected');
}

function emitAck(client, event, payload) {
  return new Promise((resolve) => {
    client.emit(event, payload, (ack) => resolve(ack));
  });
}

test('call events return explicit error acks for invalid requests', async () => {
  await waitForMongo();

  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts = Date.now();
  const caller = { id: `CALLER-${ts}`, username: `caller_${ts}` };
  const token = jwt.sign(caller, process.env.JWT_SECRET, { expiresIn: '1d' });

  let client = null;
  try {
    await User.create({
      id: caller.id,
      username: caller.username,
      hashedPassword: 'x',
      publicIdentityKeyX25519: 'x',
      publicIdentityKeyEd25519: 'x',
      signedPreKey: 'x',
      signature: 'x',
    });

    client = ioClient(`http://localhost:${port}`, {
      transports: ['websocket'],
      auth: { token },
    });
    await once(client, 'connect');

    const missingFieldsAck = await emitAck(client, 'initiateCall', { callId: `CALL-${ts}` });
    assert.equal(missingFieldsAck?.success, false);
    assert.equal(missingFieldsAck?.code, 'missing_required_fields');

    const targetOfflineAck = await emitAck(client, 'initiateCall', {
      targetUserId: `OFFLINE-${ts}`,
      callId: `CALL-${ts}`,
    });
    assert.equal(targetOfflineAck?.success, false);
    assert.equal(targetOfflineAck?.code, 'target_offline');

    const callNotFoundAck = await emitAck(client, 'acceptCall', { callId: `UNKNOWN-${ts}` });
    assert.equal(callNotFoundAck?.success, false);
    assert.equal(callNotFoundAck?.code, 'not_found');

    const invalidMediaAck = await emitAck(client, 'videoStateChanged', {
      targetUserId: '',
      isEnabled: true,
    });
    assert.equal(invalidMediaAck?.success, false);
    assert.equal(invalidMediaAck?.code, 'missing_required_fields');
  } finally {
    if (client) client.disconnect();
    await Promise.allSettled([
      Call.deleteMany({ callId: { $in: [`CALL-${ts}`, `UNKNOWN-${ts}`] } }),
      User.deleteMany({ id: caller.id }),
    ]);
    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
});
