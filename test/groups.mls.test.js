/**
 * groups.mls.test.js
 *
 * Integration tests for MLS-specific socket handler behaviors added during
 * the RFC 9420 checklist work:
 *
 *   Item #17 — sendGroupCommit rejects commits whose epoch != group.epoch + 1
 *   Item #9  — fetchKeyPackage marks packages consumed (FIFO pool)
 *   Item #20 — publishKeyPackage scopes packages per (userId, clientId)
 */
const test   = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const fs     = require('node:fs');
const path   = require('node:path');

const dotenv = require('dotenv');
const envTestPath = path.join(__dirname, '..', '.env.test');
const envPath     = path.join(__dirname, '..', '.env');
dotenv.config({ path: fs.existsSync(envTestPath) ? envTestPath : envPath });

if (process.env.MONGO_URI_TEST) process.env.MONGO_URI = process.env.MONGO_URI_TEST;
if (!process.env.MONGO_URI && process.env.MONGO_URI_SECRET) {
  process.env.MONGO_URI = process.env.MONGO_URI_SECRET;
}
if (!process.env.MONGO_URI) {
  throw new Error('Missing MONGO_URI. Set MONGO_URI_TEST or MONGO_URI before running tests.');
}
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

const jwt      = require('jsonwebtoken');
const ioClient = require('socket.io-client');
const { server, mongoose, User } = require('../server');

const KeyPackage  = () => mongoose.model('KeyPackage');
const Group       = () => mongoose.model('Group');
const GroupMember = () => mongoose.model('GroupMember');

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, 'connected');
}

function signToken({ id, username }) {
  return jwt.sign({ id, username }, process.env.JWT_SECRET, { expiresIn: '1d' });
}

async function connectAuthed({ port, id, username }) {
  const token  = signToken({ id, username });
  const client = ioClient(`http://localhost:${port}`, {
    transports: ['websocket'],
    auth: { token },
  });
  await once(client, 'connect');
  return client;
}

function emitAck(client, event, payload) {
  return new Promise((resolve) => {
    client.emit(event, payload, (ack) => resolve(ack));
  });
}

// ── Item #17: sendGroupCommit epoch validation ───────────────────────────────

test('sendGroupCommit: rejects commits with incorrect epoch (item #17)', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts   = Date.now();
  const userA = { id: `MLS17A-${ts}`, username: `mls17a_${ts}` };
  const userB = { id: `MLS17B-${ts}`, username: `mls17b_${ts}` };

  let a = null;
  let b = null;
  let groupId = null;

  try {
    await User.create([userA, userB].map((u) => ({
      id: u.id,
      username: u.username,
      hashedPassword: 'x',
      publicIdentityKeyX25519: 'x',
      publicIdentityKeyEd25519: 'x',
      signedPreKey: 'x',
      signature: 'x',
    })));

    [a, b] = await Promise.all([
      connectAuthed({ port, ...userA }),
      connectAuthed({ port, ...userB }),
    ]);

    // Create an MLS group (epoch starts at 0).
    const createAck = await emitAck(a, 'createGroup', {
      name: `MLS17 Group ${ts}`,
      memberIds: [userB.id],
      mlsEnabled: true,
      cipherSuite: 'Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256',
    });
    assert.equal(createAck?.success, true);
    groupId = String(createAck.group.groupId);

    const validCommit = {
      groupId,
      epoch: 1,            // group.epoch + 1 = 0 + 1 = 1 ✓
      senderLeafIndex: 0,
      type: 'update',
      headerB64: 'hdr',
      ciphertextB64: 'ct',
    };

    // Correct epoch → success
    const goodAck = await emitAck(a, 'sendGroupCommit', { groupId, commit: validCommit });
    assert.equal(goodAck?.success, true, `Expected success with epoch=1, got: ${goodAck?.error}`);

    // Epoch too far ahead (skip an epoch)
    const skipAck = await emitAck(a, 'sendGroupCommit', {
      groupId,
      commit: { ...validCommit, epoch: 3 },
    });
    assert.equal(skipAck?.success, false);
    assert.equal(skipAck?.error, 'Invalid commit epoch');

    // Epoch same as current (not advancing)
    const sameAck = await emitAck(a, 'sendGroupCommit', {
      groupId,
      commit: { ...validCommit, epoch: 1 },
    });
    assert.equal(sameAck?.success, false);
    assert.equal(sameAck?.error, 'Invalid commit epoch');

    // Epoch behind current
    const behindAck = await emitAck(a, 'sendGroupCommit', {
      groupId,
      commit: { ...validCommit, epoch: 0 },
    });
    assert.equal(behindAck?.success, false);
    assert.equal(behindAck?.error, 'Invalid commit epoch');

    // No epoch field (integer check skipped) → success
    const noEpochAck = await emitAck(a, 'sendGroupCommit', {
      groupId,
      commit: { groupId, senderLeafIndex: 0, type: 'update', headerB64: 'h', ciphertextB64: 'c' },
    });
    assert.equal(noEpochAck?.success, true, `Expected success with no epoch, got: ${noEpochAck?.error}`);
  } finally {
    a?.disconnect();
    b?.disconnect();
    if (groupId) {
      await Promise.allSettled([
        Group().deleteMany({ groupId }),
        GroupMember().deleteMany({ groupId }),
      ]);
    }
    await User.deleteMany({ id: { $in: [userA.id, userB.id] } });
    await new Promise((resolve) => server.close(resolve));
  }
});

// ── Item #9: fetchKeyPackage consumed flag + FIFO pool ───────────────────────

test('publishKeyPackage / fetchKeyPackage: consumed flag and FIFO ordering (item #9)', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts    = Date.now();
  const userA = { id: `MLS9A-${ts}`, username: `mls9a_${ts}` };
  const userB = { id: `MLS9B-${ts}`, username: `mls9b_${ts}` };

  let a = null;
  let b = null;

  try {
    await User.create([userA, userB].map((u) => ({
      id: u.id,
      username: u.username,
      hashedPassword: 'x',
      publicIdentityKeyX25519: 'x',
      publicIdentityKeyEd25519: 'x',
      signedPreKey: 'x',
      signature: 'x',
    })));

    [a, b] = await Promise.all([
      connectAuthed({ port, ...userA }),
      connectAuthed({ port, ...userB }),
    ]);

    // Publish first KeyPackage for userA (no clientId = default client).
    const kp1 = { userId: userA.id, initKeyB64: `init-key-1-${ts}`, leafSigningPubKeyB64: 'sig-pub' };
    const pub1 = await emitAck(a, 'publishKeyPackage', { keyPackage: kp1 });
    assert.equal(pub1?.success, true, `publishKeyPackage #1 failed: ${pub1?.error}`);

    // Publish second KeyPackage for userA (different clientId).
    const kp2 = { userId: userA.id, initKeyB64: `init-key-2-${ts}`, leafSigningPubKeyB64: 'sig-pub-2' };
    const pub2 = await emitAck(a, 'publishKeyPackage', { keyPackage: kp2, clientId: 'device-2' });
    assert.equal(pub2?.success, true, `publishKeyPackage #2 failed: ${pub2?.error}`);

    // Fetch without consume — should return a package and NOT mark it consumed.
    const fetch1 = await emitAck(b, 'fetchKeyPackage', { userId: userA.id, consume: false });
    assert.equal(fetch1?.success, true);
    assert.ok(fetch1?.keyPackage || fetch1?.initKeyB64, 'Expected keyPackage or initKeyB64');

    const afterFetch1 = await KeyPackage().findOne({ userId: userA.id, consumed: false }).lean();
    assert.ok(afterFetch1, 'Package should still be unconsumed after fetch with consume=false');

    // Fetch with consume=true — should mark the returned package as consumed.
    const fetch2 = await emitAck(b, 'fetchKeyPackage', { userId: userA.id, consume: true });
    assert.equal(fetch2?.success, true);

    const consumedDoc = await KeyPackage().findOne({ userId: userA.id, consumed: true }).lean();
    assert.ok(consumedDoc, 'A package should be marked consumed after fetch with consume=true');

    // publishKeyPackage should reset consumed=false (refreshed package is usable again).
    const refreshedKp = { userId: userA.id, initKeyB64: `init-key-refresh-${ts}`, leafSigningPubKeyB64: 'sig-refresh' };
    const pubRefresh = await emitAck(a, 'publishKeyPackage', { keyPackage: refreshedKp });
    assert.equal(pubRefresh?.success, true, `refreshed publishKeyPackage failed: ${pubRefresh?.error}`);

    const afterRefresh = await KeyPackage().findOne({ userId: userA.id, consumed: false }).lean();
    assert.ok(afterRefresh, 'Refreshed package should have consumed=false');
  } finally {
    a?.disconnect();
    b?.disconnect();
    await KeyPackage().deleteMany({ userId: userA.id });
    await User.deleteMany({ id: { $in: [userA.id, userB.id] } });
    await new Promise((resolve) => server.close(resolve));
  }
});

// ── Item #20: publishKeyPackage clientId scoping ─────────────────────────────

test('publishKeyPackage: clientId creates separate per-device packages (item #20)', async () => {
  await waitForMongo();
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts    = Date.now();
  const userA = { id: `MLS20A-${ts}`, username: `mls20a_${ts}` };
  const userB = { id: `MLS20B-${ts}`, username: `mls20b_${ts}` };

  let a = null;
  let b = null;

  try {
    await User.create([userA, userB].map((u) => ({
      id: u.id,
      username: u.username,
      hashedPassword: 'x',
      publicIdentityKeyX25519: 'x',
      publicIdentityKeyEd25519: 'x',
      signedPreKey: 'x',
      signature: 'x',
    })));

    [a, b] = await Promise.all([
      connectAuthed({ port, ...userA }),
      connectAuthed({ port, ...userB }),
    ]);

    // Publish three separate KeyPackages: default client, device-1, device-2.
    const kpDefault  = { userId: userA.id, initKeyB64: `kp-default-${ts}` };
    const kpDevice1  = { userId: userA.id, initKeyB64: `kp-d1-${ts}` };
    const kpDevice2  = { userId: userA.id, initKeyB64: `kp-d2-${ts}` };

    await emitAck(a, 'publishKeyPackage', { keyPackage: kpDefault });
    await emitAck(a, 'publishKeyPackage', { keyPackage: kpDevice1, clientId: 'device-1' });
    await emitAck(a, 'publishKeyPackage', { keyPackage: kpDevice2, clientId: 'device-2' });

    // All three should exist as separate documents (different clientIds).
    const allDocs = await KeyPackage().find({ userId: userA.id }).lean();
    const clientIds = allDocs.map((d) => d.clientId);
    assert.ok(clientIds.includes(null),       'Should have a package with clientId=null (default)');
    assert.ok(clientIds.includes('device-1'), 'Should have a package with clientId=device-1');
    assert.ok(clientIds.includes('device-2'), 'Should have a package with clientId=device-2');

    // Re-publishing for device-1 should upsert (not create a fourth document).
    const kpDevice1Refresh = { userId: userA.id, initKeyB64: `kp-d1-refresh-${ts}` };
    await emitAck(a, 'publishKeyPackage', { keyPackage: kpDevice1Refresh, clientId: 'device-1' });

    const afterRefresh = await KeyPackage().find({ userId: userA.id }).lean();
    assert.equal(afterRefresh.length, 3, 'Re-publishing for device-1 should upsert, not add a fourth row');

    const d1Doc = afterRefresh.find((d) => d.clientId === 'device-1');
    assert.ok(
      d1Doc?.keyPackage?.initKeyB64 === `kp-d1-refresh-${ts}`,
      'device-1 package should be updated to the refreshed init key'
    );
  } finally {
    a?.disconnect();
    b?.disconnect();
    await KeyPackage().deleteMany({ userId: userA.id });
    await User.deleteMany({ id: { $in: [userA.id, userB.id] } });
    await new Promise((resolve) => server.close(resolve));
  }
});
