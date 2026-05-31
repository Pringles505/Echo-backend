const test = require('node:test');
const assert = require('node:assert/strict');

const {
  registerPresenceSocketHandlers,
} = require('../src/interfaces/socket/handlers/presence.handlers');

function makeFakeSocket({ userId = 'U1' } = {}) {
  const handlers = new Map();
  const socket = {
    user: userId ? { id: userId } : null,
    join() {},
    broadcast: { emit() {} },
    emit() {},
    on(event, fn) {
      handlers.set(event, fn);
    },
  };
  return { socket, handlers };
}

function makeFakeIo() {
  const emits = [];
  const io = {
    to(roomId) {
      return {
        emit(event, payload) {
          emits.push({ roomId, event, payload });
        },
      };
    },
  };
  return { io, emits };
}

// Minimal model stubs so the connect-time pending-welcome block resolves to a
// no-op; the typing relay itself never touches the DB.
const User = { findOne: () => ({ lean: async () => ({ devices: [] }) }) };
const Message = { find: () => ({ lean: async () => [] }) };

function register({ socket, io }) {
  registerPresenceSocketHandlers({ socket, io, userSocketMap: {}, Message, User });
}

test('typing: relays peerTyping to the peer room with the typist id', () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  register({ socket, io });

  handlers.get('typing')({ targetUserId: 'U2' });

  assert.equal(emits.length, 1);
  assert.deepEqual(emits[0], {
    roomId: 'U2',
    event: 'peerTyping',
    payload: { userId: 'U1' },
  });
});

test('stopTyping: relays peerStopTyping to the peer room', () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  register({ socket, io });

  handlers.get('stopTyping')({ targetUserId: 'U2' });

  assert.equal(emits.length, 1);
  assert.equal(emits[0].roomId, 'U2');
  assert.equal(emits[0].event, 'peerStopTyping');
  assert.deepEqual(emits[0].payload, { userId: 'U1' });
});

test('typing: ignored without auth or target', () => {
  const { socket: s1, handlers: h1 } = makeFakeSocket({ userId: null });
  const { io: io1, emits: e1 } = makeFakeIo();
  register({ socket: s1, io: io1 });
  h1.get('typing')({ targetUserId: 'U2' });
  assert.equal(e1.length, 0);

  const { socket: s2, handlers: h2 } = makeFakeSocket({ userId: 'U1' });
  const { io: io2, emits: e2 } = makeFakeIo();
  register({ socket: s2, io: io2 });
  h2.get('typing')({});
  h2.get('stopTyping')({});
  assert.equal(e2.length, 0);
});
