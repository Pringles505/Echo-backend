const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createEventsService,
} = require('../src/modules/community/application/eventsService');

function makeEventModel(overrides = {}) {
  return {
    findOneAndUpdate: () => ({ lean: async () => null }),
    findOne: () => ({ lean: async () => null }),
    updateOne: async () => ({ acknowledged: true }),
    ...overrides,
  };
}

function makeEventRegistrationModel(overrides = {}) {
  return {
    create: async () => ({}),
    ...overrides,
  };
}

test('registerForEvent reserves capacity atomically via findOneAndUpdate', async () => {
  let updateFilter = null;
  let updateDoc = null;
  const Event = makeEventModel({
    findOneAndUpdate: (filter, update) => {
      updateFilter = filter;
      updateDoc = update;
      return {
        lean: async () => ({ eventId: 'E1', status: 'active', registeredCount: 1, capacity: 2 }),
      };
    },
  });
  const EventRegistration = makeEventRegistrationModel();
  const svc = createEventsService({ Event, EventRegistration });

  const result = await svc.registerForEvent({ eventId: 'E1', userId: 'U1' });

  assert.equal(result.registered, true);
  assert.equal(updateFilter.eventId, 'E1');
  assert.equal(updateFilter.status, 'active');
  assert.ok(Array.isArray(updateFilter.$or), 'capacity predicate present');
  assert.deepEqual(updateDoc, { $inc: { registeredCount: 1 } });
});

test('registerForEvent returns 409 event_full when capacity exhausted (reservation fails)', async () => {
  const Event = makeEventModel({
    findOneAndUpdate: () => ({ lean: async () => null }),
    findOne: () => ({
      lean: async () => ({ eventId: 'E1', status: 'active', registeredCount: 2, capacity: 2 }),
    }),
  });
  const EventRegistration = makeEventRegistrationModel();
  const svc = createEventsService({ Event, EventRegistration });

  await assert.rejects(
    () => svc.registerForEvent({ eventId: 'E1', userId: 'U1' }),
    (err) => err.status === 409 && err.code === 'event_full'
  );
});

test('registerForEvent returns 404 when event does not exist (reservation fails, lookup empty)', async () => {
  const Event = makeEventModel({
    findOneAndUpdate: () => ({ lean: async () => null }),
    findOne: () => ({ lean: async () => null }),
  });
  const svc = createEventsService({ Event, EventRegistration: makeEventRegistrationModel() });

  await assert.rejects(
    () => svc.registerForEvent({ eventId: 'ZZ', userId: 'U1' }),
    (err) => err.status === 404 && err.code === 'event_not_found'
  );
});

test('registerForEvent returns 400 event_not_active when status differs', async () => {
  const Event = makeEventModel({
    findOneAndUpdate: () => ({ lean: async () => null }),
    findOne: () => ({
      lean: async () => ({ eventId: 'E1', status: 'cancelled', registeredCount: 0, capacity: 100 }),
    }),
  });
  const svc = createEventsService({ Event, EventRegistration: makeEventRegistrationModel() });

  await assert.rejects(
    () => svc.registerForEvent({ eventId: 'E1', userId: 'U1' }),
    (err) => err.status === 400 && err.code === 'event_not_active'
  );
});

test('registerForEvent rolls back $inc when EventRegistration.create fails on duplicate', async () => {
  const decrementCalls = [];
  const Event = makeEventModel({
    findOneAndUpdate: () => ({
      lean: async () => ({ eventId: 'E1', status: 'active', registeredCount: 1, capacity: 10 }),
    }),
    updateOne: async (filter, update) => {
      decrementCalls.push({ filter, update });
      return { acknowledged: true };
    },
  });
  const EventRegistration = makeEventRegistrationModel({
    create: async () => {
      const err = new Error('dup');
      err.code = 11000;
      throw err;
    },
  });
  const svc = createEventsService({ Event, EventRegistration });

  await assert.rejects(
    () => svc.registerForEvent({ eventId: 'E1', userId: 'U1' }),
    (err) => err.status === 409 && err.code === 'already_registered'
  );

  assert.equal(decrementCalls.length, 1);
  assert.deepEqual(decrementCalls[0].update, { $inc: { registeredCount: -1 } });
});

test('registerForEvent rolls back $inc when EventRegistration.create throws unexpected error', async () => {
  const decrementCalls = [];
  const Event = makeEventModel({
    findOneAndUpdate: () => ({
      lean: async () => ({ eventId: 'E1', status: 'active' }),
    }),
    updateOne: async (filter, update) => {
      decrementCalls.push({ filter, update });
      return { acknowledged: true };
    },
  });
  const EventRegistration = makeEventRegistrationModel({
    create: async () => { throw new Error('boom'); },
  });
  const svc = createEventsService({ Event, EventRegistration });

  await assert.rejects(() => svc.registerForEvent({ eventId: 'E1', userId: 'U1' }));
  assert.equal(decrementCalls.length, 1);
  assert.deepEqual(decrementCalls[0].update, { $inc: { registeredCount: -1 } });
});

test('registerForEvent validates eventId and userId are strings', async () => {
  const svc = createEventsService({
    Event: makeEventModel(),
    EventRegistration: makeEventRegistrationModel(),
  });
  await assert.rejects(
    () => svc.registerForEvent({ eventId: '', userId: 'U1' }),
    (err) => err.status === 400 && err.code === 'validation_error'
  );
  await assert.rejects(
    () => svc.registerForEvent({ eventId: 'E1', userId: '' }),
    (err) => err.status === 400 && err.code === 'validation_error'
  );
});
