/**
 * Adapter exposing socket-side broadcasting to non-socket call sites
 * (e.g. HTTP routes). Keeps services framework-agnostic by accepting a
 * `notifier` instead of pulling `io`/`userSocketMap` directly.
 *
 * @param {object} deps
 * @param {*} deps.io
 * @param {Record<string,string>} deps.userSocketMap
 */
function createSocketNotifier({ io, userSocketMap }) {
  function emitToUser(userId, event, payload) {
    const socketId = userSocketMap[String(userId ?? '')];
    if (!socketId) return false;
    io.to(socketId).emit(event, payload);
    return true;
  }

  function emitToRoom(room, event, payload) {
    io.to(room).emit(event, payload);
  }

  function isUserOnline(userId) {
    return Boolean(userSocketMap[String(userId ?? '')]);
  }

  function listOnlineUserIds() {
    return Object.keys(userSocketMap);
  }

  return { emitToUser, emitToRoom, isUserOnline, listOnlineUserIds };
}

/**
 * No-op notifier for tests where no real socket layer exists.
 * @returns {ReturnType<typeof createSocketNotifier>}
 */
function createNoopNotifier() {
  const events = [];
  return {
    emitToUser: (userId, event, payload) => {
      events.push({ kind: 'user', userId, event, payload });
      return false;
    },
    emitToRoom: (room, event, payload) => {
      events.push({ kind: 'room', room, event, payload });
    },
    isUserOnline: () => false,
    listOnlineUserIds: () => [],
    events,
  };
}

module.exports = { createSocketNotifier, createNoopNotifier };
