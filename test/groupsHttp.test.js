const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');

const { createGroupsRouter } = require('../src/interfaces/http/routes/groups.route');
const { createAuthMiddleware } = require('../src/interfaces/http/middleware/auth');
const { notFoundHandler, errorHandler } = require('../src/interfaces/http/middleware/errorHandlers');
const {
  BadRequestError,
  NotFoundError,
  ForbiddenError,
  ConflictError,
} = require('../src/shared/errors');

const VALID_TOKEN = 'valid-token';
const FAKE_USER = { id: 'U1', username: 'alice' };

function makeJwtMock() {
  return {
    verify(token, _secret, cb) {
      if (token === VALID_TOKEN) return cb(null, FAKE_USER);
      return cb(new Error('invalid'));
    },
  };
}

function buildApp({ groupsService, mongoConnected = true, withAuth = true } = {}) {
  const app = express();
  app.use(express.json());
  const fakeMongoose = { connection: { readyState: mongoConnected ? 1 : 0 } };

  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
  const { requireAuth: realRequireAuth } = createAuthMiddleware({ jwt: makeJwtMock() });
  const requireAuth = withAuth ? realRequireAuth : (req, _res, next) => {
    req.user = FAKE_USER;
    next();
  };

  const router = createGroupsRouter({
    groupsService,
    mongoose: fakeMongoose,
    requireAuth,
  });
  app.use(router);
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}

function authed(req) {
  return req.set('Authorization', `Bearer ${VALID_TOKEN}`);
}

function makeService(overrides = {}) {
  return {
    createGroup: async () => ({
      group: { groupId: 'G1', name: 'Team', mlsEnabled: false, epoch: 0, cipherSuite: null },
      members: [{ userId: 'U1', leafIndex: 0 }, { userId: 'U2', leafIndex: 1 }],
    }),
    listMyGroups: async () => ({ groups: [] }),
    getGroupDetails: async () => ({
      group: { groupId: 'G1', name: 'Team' },
      membership: { role: 'admin' },
      members: [],
    }),
    addMember: async () => ({ groupId: 'G1', member: { userId: 'U3', role: 'member', leafIndex: 2 } }),
    removeMember: async () => ({ groupId: 'G1', removedMemberId: 'U2' }),
    ...overrides,
  };
}

// ---------------------------------------------------------------- POST /groups/create

test('POST /groups/create 201 returns group + members', async () => {
  const seen = [];
  const svc = makeService({
    createGroup: async (input) => {
      seen.push(input);
      return {
        group: { groupId: 'GXYZ', name: 'Squad', mlsEnabled: false, epoch: 0, cipherSuite: null },
        members: [{ userId: 'U1', leafIndex: 0 }, { userId: 'U2', leafIndex: 1 }],
      };
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/create'))
    .send({ name: 'Squad', memberIds: ['U2'] });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.equal(res.body.group.groupId, 'GXYZ');
  assert.deepEqual(seen[0].userId, 'U1');
  assert.deepEqual(seen[0].memberIds, ['U2']);
  assert.equal(seen[0].name, 'Squad');
});

test('POST /groups/create 400 when name missing', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await authed(request(app).post('/groups/create')).send({ memberIds: ['U2'] });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/create 400 when memberIds missing', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await authed(request(app).post('/groups/create')).send({ name: 'Squad' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/create 400 when memberIds is not array', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await authed(request(app).post('/groups/create')).send({ name: 'X', memberIds: 'U2' });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/create 400 when service rejects empty member list', async () => {
  const svc = makeService({
    createGroup: async () => {
      throw new BadRequestError('At least one member is required', 'validation_error', 'memberIds');
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/create')).send({ name: 'Squad', memberIds: ['U1'] });
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/create 401 without token', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await request(app).post('/groups/create').send({ name: 'Squad', memberIds: ['U2'] });
  assert.equal(res.status, 401);
});

test('POST /groups/create 503 when DB unavailable', async () => {
  const app = buildApp({ groupsService: makeService(), mongoConnected: false });
  const res = await authed(request(app).post('/groups/create')).send({ name: 'Squad', memberIds: ['U2'] });
  assert.equal(res.status, 503);
  assert.equal(res.body.code, 'database_unavailable');
});

// ---------------------------------------------------------------- GET /groups/list

test('GET /groups/list 200 returns user groups', async () => {
  const seen = [];
  const svc = makeService({
    listMyGroups: async (input) => {
      seen.push(input);
      return { groups: [{ groupId: 'G1', name: 'Team', role: 'admin' }] };
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).get('/groups/list'));
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.groups.length, 1);
  assert.equal(seen[0].userId, 'U1');
});

test('GET /groups/list 401 without token', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await request(app).get('/groups/list');
  assert.equal(res.status, 401);
});

test('GET /groups/list is matched before /groups/:groupId (route ordering)', async () => {
  let detailsCalled = false;
  const svc = makeService({
    listMyGroups: async () => ({ groups: [{ groupId: 'OK' }] }),
    getGroupDetails: async () => { detailsCalled = true; return { group: {}, membership: {}, members: [] }; },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).get('/groups/list'));
  assert.equal(res.status, 200);
  assert.equal(detailsCalled, false);
  assert.equal(res.body.groups[0].groupId, 'OK');
});

// ---------------------------------------------------------------- GET /groups/:groupId

test('GET /groups/:groupId 200 returns details', async () => {
  const seen = [];
  const svc = makeService({
    getGroupDetails: async (input) => {
      seen.push(input);
      return {
        group: { groupId: input.groupId, name: 'Team' },
        membership: { role: 'member' },
        members: [{ userId: 'U1' }],
      };
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).get('/groups/G1'));
  assert.equal(res.status, 200);
  assert.equal(res.body.group.groupId, 'G1');
  assert.equal(seen[0].userId, 'U1');
  assert.equal(seen[0].groupId, 'G1');
});

test('GET /groups/:groupId 404 when group missing', async () => {
  const svc = makeService({
    getGroupDetails: async () => { throw new NotFoundError('Group not found', 'group_not_found'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).get('/groups/UNKNOWN'));
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'group_not_found');
});

test('GET /groups/:groupId 403 when caller is not a member', async () => {
  const svc = makeService({
    getGroupDetails: async () => { throw new ForbiddenError('Not a group member', 'forbidden'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).get('/groups/G1'));
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden');
});

test('GET /groups/:groupId 401 without token', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await request(app).get('/groups/G1');
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------- POST /groups/:groupId/add-member

test('POST /groups/:groupId/add-member 200 adds member', async () => {
  const seen = [];
  const svc = makeService({
    addMember: async (input) => {
      seen.push(input);
      return { groupId: input.groupId, member: { userId: input.memberId, role: 'member', leafIndex: 4 } };
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/add-member')).send({ memberId: 'U7' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.member.userId, 'U7');
  assert.deepEqual(seen[0], { userId: 'U1', groupId: 'G1', memberId: 'U7' });
});

test('POST /groups/:groupId/add-member 400 when memberId missing', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await authed(request(app).post('/groups/G1/add-member')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/:groupId/add-member 401 without token', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await request(app).post('/groups/G1/add-member').send({ memberId: 'U7' });
  assert.equal(res.status, 401);
});

test('POST /groups/:groupId/add-member 403 when caller is not admin', async () => {
  const svc = makeService({
    addMember: async () => { throw new ForbiddenError('Only admins can add members', 'forbidden'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/add-member')).send({ memberId: 'U7' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden');
});

test('POST /groups/:groupId/add-member 404 when group missing', async () => {
  const svc = makeService({
    addMember: async () => { throw new NotFoundError('Group not found', 'group_not_found'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/add-member')).send({ memberId: 'U7' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'group_not_found');
});

test('POST /groups/:groupId/add-member 409 when already a member', async () => {
  const svc = makeService({
    addMember: async () => { throw new ConflictError('User already a member', 'already_member'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/add-member')).send({ memberId: 'U7' });
  assert.equal(res.status, 409);
  assert.equal(res.body.code, 'already_member');
});

// ---------------------------------------------------------------- POST /groups/:groupId/remove-member

test('POST /groups/:groupId/remove-member 200 removes member', async () => {
  const seen = [];
  const svc = makeService({
    removeMember: async (input) => {
      seen.push(input);
      return { groupId: input.groupId, removedMemberId: input.memberId };
    },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/remove-member')).send({ memberId: 'U2' });
  assert.equal(res.status, 200);
  assert.equal(res.body.removedMemberId, 'U2');
  assert.deepEqual(seen[0], { userId: 'U1', groupId: 'G1', memberId: 'U2' });
});

test('POST /groups/:groupId/remove-member 400 when memberId missing', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await authed(request(app).post('/groups/G1/remove-member')).send({});
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'validation_error');
});

test('POST /groups/:groupId/remove-member 403 when not allowed', async () => {
  const svc = makeService({
    removeMember: async () => { throw new ForbiddenError('Cannot remove this member', 'forbidden'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/remove-member')).send({ memberId: 'U2' });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'forbidden');
});

test('POST /groups/:groupId/remove-member 404 when target not a member', async () => {
  const svc = makeService({
    removeMember: async () => { throw new NotFoundError('User is not a member', 'not_a_member'); },
  });
  const app = buildApp({ groupsService: svc });
  const res = await authed(request(app).post('/groups/G1/remove-member')).send({ memberId: 'U2' });
  assert.equal(res.status, 404);
  assert.equal(res.body.code, 'not_a_member');
});

test('POST /groups/:groupId/remove-member 401 without token', async () => {
  const app = buildApp({ groupsService: makeService() });
  const res = await request(app).post('/groups/G1/remove-member').send({ memberId: 'U2' });
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------- service unit checks

test('createGroupsService.createGroup emits groupAdded to every member', async () => {
  const { createGroupsService } = require('../src/modules/groups/application/groupsService');
  const events = [];
  const groupRows = [];
  const memberRows = [];
  const Group = {
    create: async (doc) => { groupRows.push(doc); return doc; },
    deleteOne: async () => ({}),
  };
  const GroupMember = {
    create: async (doc) => { memberRows.push(doc); return doc; },
    deleteMany: async () => ({}),
  };
  const GroupSequence = { deleteOne: async () => ({}) };
  const notifier = {
    emitToUser: (userId, event, payload) => {
      events.push({ userId, event, payload });
    },
  };
  const svc = createGroupsService({
    Group,
    GroupMember,
    GroupSequence,
    User: null,
    ensureGroupSequence: async () => ({}),
    notifier,
  });
  const out = await svc.createGroup({
    userId: 'U1',
    name: 'Team',
    memberIds: ['U2', 'U3', 'U1'], // duplicates of self should be filtered
  });
  assert.ok(out.group.groupId.length === 5);
  assert.equal(out.members.length, 3);
  assert.equal(memberRows.length, 3);
  // groupAdded was emitted to each member exactly once
  const groupAdded = events.filter((e) => e.event === 'groupAdded');
  const recipients = groupAdded.map((e) => e.userId).sort();
  assert.deepEqual(recipients, ['U1', 'U2', 'U3']);
});

test('createGroupsService.createGroup retries on duplicate id collisions', async () => {
  const { createGroupsService } = require('../src/modules/groups/application/groupsService');
  let attempts = 0;
  const Group = {
    create: async () => {
      attempts++;
      if (attempts < 3) {
        const err = new Error('dup');
        err.code = 11000;
        throw err;
      }
      return {};
    },
    deleteOne: async () => ({}),
  };
  const GroupMember = {
    create: async () => ({}),
    deleteMany: async () => ({}),
  };
  const svc = createGroupsService({
    Group,
    GroupMember,
    GroupSequence: { deleteOne: async () => ({}) },
    User: null,
    ensureGroupSequence: async () => ({}),
    notifier: { emitToUser: () => {} },
  });
  const out = await svc.createGroup({ userId: 'U1', name: 'Team', memberIds: ['U2'] });
  assert.equal(attempts, 3);
  assert.ok(out.group.groupId);
});

test('createGroupsService.addMember rejects non-admin caller', async () => {
  const { createGroupsService } = require('../src/modules/groups/application/groupsService');
  const Group = { findOne: () => ({ lean: async () => ({ groupId: 'G1', name: 'T' }) }) };
  const GroupMember = {
    findOne: ({ userId }) => ({
      lean: async () => ({ groupId: 'G1', userId, role: 'member', leafIndex: 1 }),
    }),
    find: () => ({ lean: async () => [] }),
    create: async () => ({}),
  };
  const svc = createGroupsService({
    Group,
    GroupMember,
    ensureGroupSequence: async () => ({}),
    notifier: { emitToUser: () => {} },
  });
  await assert.rejects(
    svc.addMember({ userId: 'U1', groupId: 'G1', memberId: 'U7' }),
    (err) => err.status === 403 && err.code === 'forbidden',
  );
});

test('createGroupsService.removeMember allows self-removal even for non-admin', async () => {
  const { createGroupsService } = require('../src/modules/groups/application/groupsService');
  let deleted = null;
  const Group = { findOne: () => ({ lean: async () => ({ groupId: 'G1' }) }) };
  const GroupMember = {
    findOne: ({ userId }) => ({
      lean: async () => ({ groupId: 'G1', userId, role: 'member', leafIndex: 2 }),
    }),
    find: () => ({ lean: async () => [] }),
    deleteOne: async (q) => { deleted = q; return {}; },
  };
  const events = [];
  const svc = createGroupsService({
    Group,
    GroupMember,
    ensureGroupSequence: async () => ({}),
    notifier: { emitToUser: (uid, ev, payload) => events.push({ uid, ev, payload }) },
  });
  const out = await svc.removeMember({ userId: 'U1', groupId: 'G1', memberId: 'U1' });
  assert.deepEqual(deleted, { groupId: 'G1', userId: 'U1' });
  assert.equal(out.removedMemberId, 'U1');
  // groupRemoved is emitted to the user that left
  const removed = events.find((e) => e.ev === 'groupRemoved');
  assert.ok(removed);
  assert.equal(removed.uid, 'U1');
});
