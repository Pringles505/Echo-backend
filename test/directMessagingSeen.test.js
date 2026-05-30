const test = require('node:test');
const assert = require('node:assert/strict');

const {
  registerDirectMessagingSocketHandlers,
} = require('../src/interfaces/socket/handlers/directMessaging.handlers');

function makeFakeSocket({ userId = 'U1' } = {}) {
  const handlers = new Map();
  const socket = {
    user: userId ? { id: userId } : null,
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

function makeMessage() {
  const calls = [];
  const Message = {
    async updateMany(filter, update) {
      calls.push({ filter, update });
      return { modifiedCount: 2 };
    },
  };
  return { Message, calls };
}

function register({ socket, io, Message }) {
  registerDirectMessagingSocketHandlers({
    socket,
    io,
    userSocketMap: {},
    Message,
    User: {},
    MessageSequence: {},
    makeConversationKey: () => 'unused',
    ensureConversationSequence: async () => ({}),
  });
}

test('messageSeen: marks inbound unread seen and stamps seenAt', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageSeen')({ targetUserId: 'U2' });

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].filter, {
    userId: 'U2',
    targetUserId: 'U1',
    seenStatus: false,
  });
  assert.equal(calls[0].update.$set.seenStatus, true);
  assert.ok(calls[0].update.$set.seenAt instanceof Date);
});

test('messageSeen: notifies both the sender room and the readers own siblings', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  const { Message } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageSeen')({ targetUserId: 'U2' });

  assert.equal(emits.length, 2);
  const rooms = emits.map((e) => e.roomId).sort();
  assert.deepEqual(rooms, ['U1', 'U2']);
  for (const e of emits) {
    assert.equal(e.event, 'messageSeenUpdate');
    assert.equal(e.payload.userId, 'U1');
    assert.equal(e.payload.targetUserId, 'U2');
    assert.equal(typeof e.payload.seenAt, 'string');
  }
});

test('messageSeen: scopes the update to a conversationKey when provided', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageSeen')({ targetUserId: 'U2', conversationKey: 'ckey-123' });

  assert.equal(calls[0].filter.conversationKey, 'ckey-123');
});

test('messageSeen: only emits to the self room once when reading own messages', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  const { Message } = makeMessage();
  register({ socket, io, Message });

  // Self-conversation edge case: targetUserId === authedUserId must not
  // double-emit to the same room.
  await handlers.get('messageSeen')({ targetUserId: 'U1' });

  assert.equal(emits.length, 1);
  assert.equal(emits[0].roomId, 'U1');
});

test('messageSeen: ignores unauthenticated sockets', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: null });
  const { io, emits } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageSeen')({ targetUserId: 'U2' });

  assert.equal(calls.length, 0);
  assert.equal(emits.length, 0);
});

test('messageSeen: ignores payloads without a targetUserId', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageSeen')({});

  assert.equal(calls.length, 0);
  assert.equal(emits.length, 0);
});

// ------------------------------------------------------------ messageDelivered

test('messageDelivered: stamps deliveredAt on undelivered inbound only', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageDelivered')({ targetUserId: 'U2' });

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].filter, {
    userId: 'U2',
    targetUserId: 'U1',
    deliveredAt: null,
  });
  assert.ok(calls[0].update.$set.deliveredAt instanceof Date);
  // Delivered must never set seenStatus/seenAt — that's a separate signal.
  assert.equal('seenStatus' in calls[0].update.$set, false);
});

test('messageDelivered: notifies only the original sender room', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io, emits } = makeFakeIo();
  const { Message } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageDelivered')({ targetUserId: 'U2' });

  assert.equal(emits.length, 1);
  assert.equal(emits[0].roomId, 'U2');
  assert.equal(emits[0].event, 'messageDeliveredUpdate');
  assert.equal(emits[0].payload.userId, 'U1');
  assert.equal(emits[0].payload.targetUserId, 'U2');
  assert.equal(typeof emits[0].payload.deliveredAt, 'string');
});

test('messageDelivered: scopes to a conversationKey when provided', async () => {
  const { socket, handlers } = makeFakeSocket({ userId: 'U1' });
  const { io } = makeFakeIo();
  const { Message, calls } = makeMessage();
  register({ socket, io, Message });

  await handlers.get('messageDelivered')({ targetUserId: 'U2', conversationKey: 'ck-9' });

  assert.equal(calls[0].filter.conversationKey, 'ck-9');
});

test('messageDelivered: ignores self, unauth, and missing target', async () => {
  const { socket: s1, handlers: h1 } = makeFakeSocket({ userId: 'U1' });
  const { io: io1, emits: e1 } = makeFakeIo();
  const { Message: M1, calls: c1 } = makeMessage();
  register({ socket: s1, io: io1, Message: M1 });
  await h1.get('messageDelivered')({ targetUserId: 'U1' }); // self
  await h1.get('messageDelivered')({}); // missing target
  assert.equal(c1.length, 0);
  assert.equal(e1.length, 0);

  const { socket: s2, handlers: h2 } = makeFakeSocket({ userId: null });
  const { io: io2, emits: e2 } = makeFakeIo();
  const { Message: M2, calls: c2 } = makeMessage();
  register({ socket: s2, io: io2, Message: M2 });
  await h2.get('messageDelivered')({ targetUserId: 'U2' }); // unauth
  assert.equal(c2.length, 0);
  assert.equal(e2.length, 0);
});
