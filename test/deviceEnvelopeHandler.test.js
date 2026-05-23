const test = require('node:test');
const assert = require('node:assert/strict');

const handlerModule = require('../src/interfaces/socket/handlers/deviceEnvelope.handlers');
const { registerDeviceEnvelopeSocketHandlers, _internal } = handlerModule;

function makeFakeSocket({ userId = 'U1' } = {}) {
  const handlers = new Map();
  const toCalls = [];
  const socket = {
    user: userId ? { id: userId } : null,
    on(event, fn) { handlers.set(event, fn); },
    to(roomId) {
      return {
        emit(event, payload) { toCalls.push({ roomId, event, payload }); },
      };
    },
  };
  return { socket, handlers, toCalls };
}

test.beforeEach(() => {
  // Clear the in-memory buckets between tests so rate-limit state doesn't leak.
  _internal.sendBuckets.clear();
});

test('deviceEnvelope: drops payloads without ciphertext', () => {
  const { socket, handlers, toCalls } = makeFakeSocket();
  registerDeviceEnvelopeSocketHandlers({ socket });
  const fn = handlers.get('deviceEnvelope');

  fn(null);
  fn({});
  fn({ text: 'plaintext leak attempt' });
  fn({ ciphertext: '' });

  assert.equal(toCalls.length, 0);
});

test('deviceEnvelope: relays opaque ciphertext to the sender room (siblings only)', () => {
  const { socket, handlers, toCalls } = makeFakeSocket({ userId: 'U42' });
  registerDeviceEnvelopeSocketHandlers({ socket });
  const fn = handlers.get('deviceEnvelope');

  fn({ ciphertext: 'opaque-ct', nonce: 'n', recipientDeviceId: 'D2' });

  assert.equal(toCalls.length, 1);
  assert.equal(toCalls[0].roomId, 'U42');
  assert.equal(toCalls[0].event, 'deviceEnvelope');
  assert.equal(toCalls[0].payload.ciphertext, 'opaque-ct');
});

test('deviceEnvelope: ignores events from unauthenticated sockets', () => {
  const { socket, handlers, toCalls } = makeFakeSocket({ userId: null });
  registerDeviceEnvelopeSocketHandlers({ socket });
  const fn = handlers.get('deviceEnvelope');

  fn({ ciphertext: 'opaque-ct' });

  assert.equal(toCalls.length, 0);
});

test('deviceEnvelope: enforces a per-user rate limit', () => {
  const max = 5;
  const userId = 'U-rate';
  // The handler reads RATE_LIMIT_ENVELOPES_PER_MIN at import time. We can't
  // override that without re-requiring, so we exercise the helper directly.
  for (let i = 0; i < max; i += 1) {
    assert.equal(_internal.takeTokenForUser(userId, max), true);
  }
  assert.equal(_internal.takeTokenForUser(userId, max), false);

  // Different user has its own bucket.
  assert.equal(_internal.takeTokenForUser('U-other', max), true);
});

test('deviceSessionRequest: requires a targetUserId', () => {
  const { socket, handlers, toCalls } = makeFakeSocket({ userId: 'U7' });
  registerDeviceEnvelopeSocketHandlers({ socket });
  const fn = handlers.get('deviceSessionRequest');

  fn({});
  fn({ targetUserId: '' });
  fn({ targetUserId: 123 });
  fn({ targetUserId: 'V9' });

  assert.equal(toCalls.length, 1);
  assert.equal(toCalls[0].event, 'deviceSessionRequest');
  assert.deepEqual(toCalls[0].payload, { targetUserId: 'V9' });
});
