const { RATE_LIMIT_ENVELOPES_PER_MIN } = require('../../../shared/constants');

const RATE_WINDOW_MS = 60_000;

// In-memory per-account token bucket. The relay never reads the payload, so
// this is purely flood control: N envelopes/min per user across all their
// sockets. Bucket keyed by parent userId so a malicious client with many
// tabs still hits the same limit.
const sendBuckets = new Map();

function takeTokenForUser(userId, max = RATE_LIMIT_ENVELOPES_PER_MIN) {
  if (!userId) return false;
  const now = Date.now();
  const existing = sendBuckets.get(userId);
  if (!existing || existing.resetAt <= now) {
    sendBuckets.set(userId, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (existing.count >= max) {
    return false;
  }
  existing.count += 1;
  return true;
}

function isValidEnvelopePayload(payload) {
  if (!payload || typeof payload !== 'object') return false;
  // Require an opaque `ciphertext` string. Plaintext relay is intentionally
  // unsupported here so a frontend regression can't leak plaintext through
  // this channel.
  if (typeof payload.ciphertext !== 'string' || payload.ciphertext.length === 0) {
    return false;
  }
  return true;
}

// Relays encrypted device-to-device envelopes to the user's other active
// devices in real time. Every authenticated socket already joins a room
// named socket.user.id (presence.handlers.js), so `socket.to(userId)`
// delivers to all OTHER sockets and excludes the sender.
function registerDeviceEnvelopeSocketHandlers({ socket }) {
  socket.on('deviceEnvelope', (payload) => {
    const userId = socket.user?.id;
    if (!userId) return;
    if (!isValidEnvelopePayload(payload)) return;
    if (!takeTokenForUser(userId)) return;
    socket.to(userId).emit('deviceEnvelope', payload);
  });

  // Relay session-state requests to all other devices of the same account.
  // Any device that has current session state for the requested conversation
  // will respond with a sessionSync device envelope.
  socket.on('deviceSessionRequest', (payload = {}) => {
    const userId = socket.user?.id;
    const targetUserId = payload?.targetUserId;
    if (!userId || typeof targetUserId !== 'string' || targetUserId.length === 0) return;
    if (!takeTokenForUser(userId)) return;
    socket.to(userId).emit('deviceSessionRequest', { targetUserId });
  });
}

module.exports = { registerDeviceEnvelopeSocketHandlers, _internal: { takeTokenForUser, sendBuckets } };
