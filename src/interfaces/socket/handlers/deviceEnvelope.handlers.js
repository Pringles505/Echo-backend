const { RATE_LIMIT_ENVELOPES_PER_MIN } = require('../../../shared/constants');

const RATE_WINDOW_MS = 60_000;

/**
 * In-memory per-account token bucket. The relay never reads the payload, so
 * this is purely a flood-control mechanism — N envelopes/min per user across
 * all their connected sockets.
 *
 * Fan-in scales by parent userId, not by socket, so a malicious client with
 * many tabs still hits the same bucket.
 */
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
  // The relay does not decode the payload, but we DO require that the payload
  // carry an opaque `ciphertext` string. Plaintext relay (the C2 finding from
  // the front audit) is intentionally not supported by this handler.
  if (typeof payload.ciphertext !== 'string' || payload.ciphertext.length === 0) {
    return false;
  }
  return true;
}

/**
 * Relays encrypted device-to-device envelopes to all other active devices
 * of the same user account in real time.
 *
 * Every authenticated socket already joins a room named socket.user.id
 * (see presence.handlers.js). Emitting to that room with socket.to()
 * delivers only to OTHER sockets — the sender is excluded automatically.
 *
 * Contract:
 *   - The payload MUST be opaque ciphertext encrypted by the sender device
 *     under a per-recipient Double Ratchet session. The server does not (and
 *     should not) be able to decrypt anything.
 *   - Plaintext payloads are dropped server-side: this prevents accidental
 *     plaintext leakage if a frontend regresses.
 *   - A simple per-user rate limit caps `deviceEnvelope` emits at N/minute.
 */
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
