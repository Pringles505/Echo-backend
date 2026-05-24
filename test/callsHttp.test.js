const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createCallsRouter } = require('../src/interfaces/http/routes/calls.route');
const { createCallsService } = require('../src/modules/calls/application/callsService');
const {
  BadRequestError,
  NotFoundError,
  ForbiddenError,
} = require('../src/shared/errors');
const {
  notFoundHandler,
  errorHandler,
} = require('../src/interfaces/http/middleware/errorHandlers');

function buildApp({
  callsService,
  mongoConnected = true,
  authenticated = true,
  user = { id: 'CALLER1', username: 'caller' },
} = {}) {
  const app = express();
  app.use(express.json());

  const requireAuth = (req, res, next) => {
    if (!authenticated) {
      return res
        .status(401)
        .json({ success: false, error: 'Unauthorized', code: 'unauthorized' });
    }
    req.user = user;
    return next();
  };

  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };
  app.use(createCallsRouter({ callsService, mongoose: fakeMongoose, requireAuth }));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function stubService(overrides = {}) {
  return {
    initiateCall: async () => ({ status: 'ringing' }),
    acceptCall: async () => ({ status: 'in-progress' }),
    declineCall: async () => ({ status: 'declined' }),
    endCall: async () => ({ status: 'ended', duration: 12 }),
    updateMediaState: async () => ({ mediaType: 'video', isEnabled: true }),
    ...overrides,
  };
}

test('POST /calls/initiate returns 200 with status ringing on success', async () => {
  const seen = [];
  const callsService = stubService({
    initiateCall: async (input) => {
      seen.push(input);
      return { status: 'ringing' };
    },
  });
  const app = buildApp({ callsService });

  const res = await request(app)
    .post('/calls/initiate')
    .send({ targetUserId: 'TARGET', callId: 'CALL-1' });

  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, status: 'ringing' });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].callerId, 'CALLER1');
  assert.equal(seen[0].callerName, 'caller');
  assert.equal(seen[0].targetUserId, 'TARGET');
  assert.equal(seen[0].callId, 'CALL-1');
});

test('POST /calls/initiate returns 401 without auth', async () => {
  const app = buildApp({ callsService: stubService(), authenticated: false });
  const res = await request(app)
    .post('/calls/initiate')
    .send({ targetUserId: 'X', callId: 'Y' });
  assert.equal(res.status, 401);
  assert.equal(res.body.code, 'unauthorized');
});

test('POST /calls/initiate returns 400 on missing fields', async () => {
  const app = buildApp({ callsService: stubService() });
  const res = await request(app).post('/calls/initiate').send({ callId: 'only' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /calls/initiate returns 400 with target_offline code', async () => {
  const callsService = stubService({
    initiateCall: async () => {
      throw new BadRequestError('Target user is offline', 'target_offline');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app)
    .post('/calls/initiate')
    .send({ targetUserId: 'OFF', callId: 'C' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'target_offline');
});

test('POST /calls/accept returns 200 with status in-progress', async () => {
  const seen = [];
  const callsService = stubService({
    acceptCall: async (input) => {
      seen.push(input);
      return { status: 'in-progress' };
    },
  });
  const app = buildApp({ callsService });

  const res = await request(app).post('/calls/accept').send({ callId: 'CALL-X' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, status: 'in-progress' });
  assert.equal(seen[0].userId, 'CALLER1');
  assert.equal(seen[0].callId, 'CALL-X');
});

test('POST /calls/accept returns 404 when call not found', async () => {
  const callsService = stubService({
    acceptCall: async () => {
      throw new NotFoundError('Call not found', 'not_found');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/accept').send({ callId: 'GHOST' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'not_found');
});

test('POST /calls/accept returns 403 when caller is not a participant', async () => {
  const callsService = stubService({
    acceptCall: async () => {
      throw new ForbiddenError('Not a participant', 'forbidden');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/accept').send({ callId: 'C' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden');
});

test('POST /calls/accept returns 400 when callId missing', async () => {
  const app = buildApp({ callsService: stubService() });
  const res = await request(app).post('/calls/accept').send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /calls/accept returns 401 without auth', async () => {
  const app = buildApp({ callsService: stubService(), authenticated: false });
  const res = await request(app).post('/calls/accept').send({ callId: 'C' });
  assert.equal(res.status, 401);
});

test('POST /calls/decline returns 200 with status declined', async () => {
  const callsService = stubService();
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/decline').send({ callId: 'C' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, status: 'declined' });
});

test('POST /calls/decline propagates 404', async () => {
  const callsService = stubService({
    declineCall: async () => {
      throw new NotFoundError('Call not found', 'not_found');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/decline').send({ callId: 'GHOST' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'not_found');
});

test('POST /calls/decline propagates 403', async () => {
  const callsService = stubService({
    declineCall: async () => {
      throw new ForbiddenError('forbidden', 'forbidden');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/decline').send({ callId: 'C' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden');
});

test('POST /calls/end returns 200 with duration', async () => {
  const callsService = stubService({
    endCall: async () => ({ status: 'ended', duration: 42 }),
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/end').send({ callId: 'C' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, status: 'ended', duration: 42 });
});

test('POST /calls/end returns 401 without auth', async () => {
  const app = buildApp({ callsService: stubService(), authenticated: false });
  const res = await request(app).post('/calls/end').send({ callId: 'C' });
  assert.equal(res.status, 401);
});

test('POST /calls/end returns 403 when forbidden', async () => {
  const callsService = stubService({
    endCall: async () => {
      throw new ForbiddenError('forbidden', 'forbidden');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app).post('/calls/end').send({ callId: 'C' });
  assert.equal(res.status, 403);
});

test('POST /calls/end returns 400 when callId missing', async () => {
  const app = buildApp({ callsService: stubService() });
  const res = await request(app).post('/calls/end').send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /calls/media-state returns 200 for video', async () => {
  const seen = [];
  const callsService = stubService({
    updateMediaState: async (input) => {
      seen.push(input);
      return { mediaType: input.mediaType, isEnabled: input.isEnabled };
    },
  });
  const app = buildApp({ callsService });

  const res = await request(app)
    .post('/calls/media-state')
    .send({ targetUserId: 'PEER', mediaType: 'video', isEnabled: false });

  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { success: true, mediaType: 'video', isEnabled: false });
  assert.equal(seen[0].userId, 'CALLER1');
  assert.equal(seen[0].targetUserId, 'PEER');
});

test('POST /calls/media-state rejects invalid mediaType with 400', async () => {
  const app = buildApp({ callsService: stubService() });
  const res = await request(app)
    .post('/calls/media-state')
    .send({ targetUserId: 'PEER', mediaType: 'screen', isEnabled: true });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /calls/media-state returns 400 with target_offline code', async () => {
  const callsService = stubService({
    updateMediaState: async () => {
      throw new BadRequestError('Target user is offline', 'target_offline');
    },
  });
  const app = buildApp({ callsService });
  const res = await request(app)
    .post('/calls/media-state')
    .send({ targetUserId: 'OFF', mediaType: 'audio', isEnabled: true });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'target_offline');
});

test('POST /calls/media-state returns 401 without auth', async () => {
  const app = buildApp({ callsService: stubService(), authenticated: false });
  const res = await request(app)
    .post('/calls/media-state')
    .send({ targetUserId: 'P', mediaType: 'audio', isEnabled: true });
  assert.equal(res.status, 401);
});

test('POST /calls/media-state returns 400 when isEnabled has wrong type', async () => {
  const app = buildApp({ callsService: stubService() });
  const res = await request(app)
    .post('/calls/media-state')
    .send({ targetUserId: 'P', mediaType: 'audio', isEnabled: 'yes' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /calls/initiate returns 503 when database is offline', async () => {
  const app = buildApp({ callsService: stubService(), mongoConnected: false });
  const res = await request(app)
    .post('/calls/initiate')
    .send({ targetUserId: 'T', callId: 'C' });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

function makeFakeCallStore() {
  const calls = new Map();
  return {
    calls,
    Call: class FakeCall {
      constructor(data) {
        Object.assign(this, data);
      }
      async save() {
        calls.set(this.callId, this);
        return this;
      }
      static async findOne(query) {
        return calls.get(query.callId) || null;
      }
      static async findOneAndUpdate(query, update) {
        const doc = calls.get(query.callId);
        if (!doc) return null;
        Object.assign(doc, update.$set || {});
        return doc;
      }
    },
  };
}

function makeFakeNotifier({ online = true } = {}) {
  const events = [];
  return {
    emitToUser(userId, event, payload) {
      events.push({ userId, event, payload });
      return true;
    },
    isUserOnline() {
      return online;
    },
    events,
  };
}

test('callsService.initiateCall persists call and emits incomingCall', async () => {
  const { Call, calls } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const eventCalls = [];
  const callEventService = {
    createCallEventMessage: async (input) => {
      eventCalls.push(input);
      return null;
    },
  };
  const service = createCallsService({
    Call,
    callEventService,
    notifier,
    scheduleTimeout: () => {},
  });

  const result = await service.initiateCall({
    callerId: 'A',
    callerName: 'alice',
    targetUserId: 'B',
    callId: 'CALL-1',
  });

  assert.deepEqual(result, { status: 'ringing' });
  assert.equal(calls.size, 1);
  assert.equal(calls.get('CALL-1').status, 'ringing');
  assert.equal(notifier.events[0].event, 'incomingCall');
  assert.equal(notifier.events[0].userId, 'B');
  assert.deepEqual(notifier.events[0].payload, {
    callId: 'CALL-1',
    callerId: 'A',
    callerName: 'alice',
  });
});

test('callsService.initiateCall throws target_offline when notifier reports offline', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier({ online: false });
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
    scheduleTimeout: () => {},
  });

  await assert.rejects(
    () => service.initiateCall({ callerId: 'A', targetUserId: 'B', callId: 'C' }),
    (err) => err.status === 400 && err.code === 'target_offline'
  );
});

test('callsService.acceptCall rejects non-participants with 403', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
  });
  await new Call({
    callId: 'CALL-2',
    callerId: 'A',
    receiverId: 'B',
    status: 'ringing',
    startedAt: new Date(),
  }).save();

  await assert.rejects(
    () => service.acceptCall({ userId: 'C', callId: 'CALL-2' }),
    (err) => err.status === 403 && err.code === 'forbidden'
  );
});

test('callsService.acceptCall returns 404 when call not found', async () => {
  const { Call } = makeFakeCallStore();
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier: makeFakeNotifier(),
  });
  await assert.rejects(
    () => service.acceptCall({ userId: 'A', callId: 'GHOST' }),
    (err) => err.status === 404 && err.code === 'not_found'
  );
});

test('callsService.endCall calculates duration and creates event message', async () => {
  const { Call, calls } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const eventCalls = [];
  const callEventService = {
    createCallEventMessage: async (input) => {
      eventCalls.push(input);
      return null;
    },
  };
  const service = createCallsService({ Call, callEventService, notifier });

  const startedAt = new Date(Date.now() - 5000);
  await new Call({
    callId: 'CALL-3',
    callerId: 'A',
    receiverId: 'B',
    status: 'in-progress',
    startedAt,
  }).save();

  const result = await service.endCall({ userId: 'A', callId: 'CALL-3' });
  assert.equal(result.status, 'ended');
  assert.ok(result.duration >= 4 && result.duration <= 7, 'duration ~5s');
  assert.equal(calls.get('CALL-3').status, 'ended');
  assert.equal(eventCalls.length, 1);
  assert.equal(eventCalls[0].status, 'ended');
  assert.equal(notifier.events.find((e) => e.event === 'callEnded')?.userId, 'B');
});

test('callsService.declineCall emits callDeclined to caller and creates event', async () => {
  const { Call, calls } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const eventCalls = [];
  const service = createCallsService({
    Call,
    callEventService: {
      createCallEventMessage: async (input) => {
        eventCalls.push(input);
        return null;
      },
    },
    notifier,
  });

  await new Call({
    callId: 'CALL-4',
    callerId: 'A',
    receiverId: 'B',
    status: 'ringing',
    startedAt: new Date(),
  }).save();

  const result = await service.declineCall({ userId: 'B', callId: 'CALL-4' });
  assert.deepEqual(result, { status: 'declined' });
  assert.equal(calls.get('CALL-4').status, 'declined');
  assert.equal(eventCalls[0].status, 'declined');
  assert.equal(notifier.events[0].event, 'callDeclined');
  assert.equal(notifier.events[0].userId, 'A');
});

test('callsService.updateMediaState emits videoStateChanged to peer', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
  });

  const result = await service.updateMediaState({
    userId: 'A',
    targetUserId: 'B',
    mediaType: 'video',
    isEnabled: false,
  });
  assert.deepEqual(result, { mediaType: 'video', isEnabled: false });
  assert.equal(notifier.events[0].event, 'videoStateChanged');
  assert.deepEqual(notifier.events[0].payload, { isEnabled: false });
});

test('callsService.updateMediaState emits audioStateChanged for audio', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
  });

  await service.updateMediaState({
    userId: 'A',
    targetUserId: 'B',
    mediaType: 'audio',
    isEnabled: true,
  });
  assert.equal(notifier.events[0].event, 'audioStateChanged');
});

test('callsService.updateMediaState target_offline when peer is offline', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier({ online: false });
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
  });
  await assert.rejects(
    () =>
      service.updateMediaState({
        userId: 'A',
        targetUserId: 'B',
        mediaType: 'audio',
        isEnabled: true,
      }),
    (err) => err.status === 400 && err.code === 'target_offline'
  );
});

test('callsService scheduled missed-check marks ringing call as missed', async () => {
  const { Call, calls } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const eventCalls = [];
  let scheduled = null;
  const service = createCallsService({
    Call,
    callEventService: {
      createCallEventMessage: async (input) => {
        eventCalls.push(input);
        return null;
      },
    },
    notifier,
    scheduleTimeout: (fn) => {
      scheduled = fn;
    },
  });

  await service.initiateCall({
    callerId: 'A',
    targetUserId: 'B',
    callId: 'CALL-MISS',
  });
  assert.equal(typeof scheduled, 'function');

  await scheduled();
  assert.equal(calls.get('CALL-MISS').status, 'missed');
  assert.equal(eventCalls[0].status, 'missed');
});

test('callsService scheduled missed-check is no-op if call already accepted', async () => {
  const { Call, calls } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  const eventCalls = [];
  let scheduled = null;
  const service = createCallsService({
    Call,
    callEventService: {
      createCallEventMessage: async (input) => {
        eventCalls.push(input);
        return null;
      },
    },
    notifier,
    scheduleTimeout: (fn) => {
      scheduled = fn;
    },
  });

  await service.initiateCall({
    callerId: 'A',
    targetUserId: 'B',
    callId: 'CALL-ACK',
  });
  await service.acceptCall({ userId: 'B', callId: 'CALL-ACK' });
  await scheduled();

  assert.equal(calls.get('CALL-ACK').status, 'in-progress');
  assert.equal(eventCalls.length, 0);
});

test('callsService scheduled missed-check tolerates already-deleted calls', async () => {
  const { Call } = makeFakeCallStore();
  const notifier = makeFakeNotifier();
  let scheduled = null;
  const service = createCallsService({
    Call,
    callEventService: { createCallEventMessage: async () => null },
    notifier,
    scheduleTimeout: (fn) => {
      scheduled = fn;
    },
  });

  await service.initiateCall({
    callerId: 'A',
    targetUserId: 'B',
    callId: 'CALL-DEL',
  });
  Call.findOne = async () => null;
  await assert.doesNotReject(() => scheduled());
});
