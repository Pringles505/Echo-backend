/**
 * Relays encrypted device-to-device envelopes to all other active devices
 * of the same user account in real time.
 *
 * Every authenticated socket already joins a room named socket.user.id
 * (see presence.handlers.js). Emitting to that room with socket.to()
 * delivers only to OTHER sockets — the sender is excluded automatically.
 *
 * The payload is opaque AES-GCM ciphertext derived from the shared identity
 * key, so the server cannot read it.
 */
function registerDeviceEnvelopeSocketHandlers({ socket }) {
  socket.on('deviceEnvelope', (payload) => {
    const userId = socket.user?.id
    if (!userId) return
    socket.to(userId).emit('deviceEnvelope', payload)
  })

  // Relay session-state requests to all other devices of the same account.
  // Any device that has current session state for the requested conversation
  // will respond with a sessionSync device envelope.
  socket.on('deviceSessionRequest', ({ targetUserId } = {}) => {
    const userId = socket.user?.id
    if (!userId || !targetUserId) return
    socket.to(userId).emit('deviceSessionRequest', { targetUserId })
  })
}

module.exports = { registerDeviceEnvelopeSocketHandlers }
