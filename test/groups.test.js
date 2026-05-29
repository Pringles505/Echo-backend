const test = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const fs = require("node:fs");
const path = require("node:path");

// Load test env vars from Echo-backend/.env.test (preferred) or Echo-backend/.env
const dotenv = require("dotenv");
const envTestPath = path.join(__dirname, "..", ".env.test");
const envPath = path.join(__dirname, "..", ".env");
dotenv.config({ path: fs.existsSync(envTestPath) ? envTestPath : envPath });

// Prefer an explicit test DB so you don't pollute your real DB.
// Set this before importing server.js because it connects at import time.
if (process.env.MONGO_URI_TEST) {
  process.env.MONGO_URI = process.env.MONGO_URI_TEST;
}

if (!process.env.MONGO_URI && process.env.MONGO_URI_SECRET) {
  process.env.MONGO_URI = process.env.MONGO_URI_SECRET;
}

if (!process.env.MONGO_URI) {
  throw new Error(
    "Missing MONGO_URI. Set MONGO_URI_TEST (recommended), MONGO_URI, or MONGO_URI_SECRET before running tests."
  );
}

process.env.JWT_SECRET = process.env.JWT_SECRET || "test-secret";

const jwt = require("jsonwebtoken");
const ioClient = require("socket.io-client");
const { server, mongoose, Message, User } = require("../server");

const Group = () => mongoose.model("Group");
const GroupMember = () => mongoose.model("GroupMember");
const GroupSequence = () => mongoose.model("GroupSequence");
const Device = () => mongoose.model("Device");

async function waitForMongo() {
  if (mongoose.connection.readyState === 1) return;
  await once(mongoose.connection, "connected");
}

function signToken({ id, username }) {
  return jwt.sign({ id, username }, process.env.JWT_SECRET, { expiresIn: "1d" });
}

async function connectAuthed({ port, id, username }) {
  const token = signToken({ id, username });
  const client = ioClient(`http://localhost:${port}`, {
    transports: ["websocket"],
    auth: { token },
  });
  await once(client, "connect");
  return client;
}

function emitAck(client, event, payload) {
  return new Promise((resolve) => {
    client.emit(event, payload, (ack) => resolve(ack));
  });
}

test("group system: create/list/open/send/add/remove (happy path + authz)", async () => {
  await waitForMongo();

  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();

  const ts = Date.now();
  const userA = { id: `GA-${ts}`, username: `ga_${ts}` };
  const userB = { id: `GB-${ts}`, username: `gb_${ts}` };
  const userC = { id: `GC-${ts}`, username: `gc_${ts}` };
  const userD = { id: `GD-${ts}`, username: `gd_${ts}` };
  const userE = { id: `GE-${ts}`, username: `ge_${ts}` }; // non-member

  const createdUserIds = [userA.id, userB.id, userC.id, userD.id, userE.id];
  const createdGroupIds = [];

  let a = null;
  let b = null;
  let c = null;
  let d = null;
  let e = null;
  let bDevice = null;

  try {
    await User.create(
      [userA, userB, userC, userD, userE].map((u) => ({
        id: u.id,
        username: u.username,
        hashedPassword: "x",
        publicIdentityKeyX25519: "x",
        publicIdentityKeyEd25519: "x",
        signedPreKey: "x",
        signature: "x",
      }))
    );

    [a, b, c, d, e] = await Promise.all([
      connectAuthed({ port, ...userA }),
      connectAuthed({ port, ...userB }),
      connectAuthed({ port, ...userC }),
      connectAuthed({ port, ...userD }),
      connectAuthed({ port, ...userE }),
    ]);

    const groupName = `Test Group ${ts}`;

    // Members should be notified via groupAdded when online.
    const bGroupAddedP = once(b, "groupAdded");
    const cGroupAddedP = once(c, "groupAdded");

    const createAck = await emitAck(a, "createGroup", {
      name: groupName,
      memberIds: [userB.id, userC.id],
    });

    assert.equal(createAck?.success, true);
    assert.ok(createAck?.group?.groupId);
    assert.equal(createAck?.group?.name, groupName);

    const groupId = String(createAck.group.groupId);
    createdGroupIds.push(groupId);

    const [bAddedPayload] = await bGroupAddedP;
    const [cAddedPayload] = await cGroupAddedP;

    assert.equal(String(bAddedPayload.groupId), groupId);
    assert.equal(String(cAddedPayload.groupId), groupId);
    assert.equal(bAddedPayload.name, groupName);
    assert.equal(cAddedPayload.name, groupName);

    // DB sanity: group exists, members exist, sequence initialized.
    const [groupDoc, seqDoc, members] = await Promise.all([
      Group().findOne({ groupId }).lean(),
      GroupSequence().findOne({ groupId }).lean(),
      GroupMember().find({ groupId }).lean(),
    ]);
    assert.ok(groupDoc);
    assert.ok(seqDoc);
    assert.equal(seqDoc.lastSequenceNumber, -1);
    assert.equal(groupDoc.mlsEnabled, false);
    assert.equal(groupDoc.epoch, 0);
    assert.equal(groupDoc.cipherSuite, null);

    const roles = new Map(members.map((m) => [String(m.userId), m.role]));
    const leafIndexes = new Map(members.map((m) => [String(m.userId), m.leafIndex]));
    const statuses = new Map(members.map((m) => [String(m.userId), m.status]));
    assert.equal(roles.get(userA.id), "admin");
    assert.equal(roles.get(userB.id), "member");
    assert.equal(roles.get(userC.id), "member");
    assert.equal(leafIndexes.get(userA.id), 0);
    assert.equal(leafIndexes.get(userB.id), 1);
    assert.equal(leafIndexes.get(userC.id), 2);
    assert.equal(statuses.get(userA.id), "active");
    assert.equal(statuses.get(userB.id), "active");
    assert.equal(statuses.get(userC.id), "active");

    // listMyGroups for B
    const listAck = await emitAck(b, "listMyGroups", {});
    assert.equal(listAck?.success, true);
    assert.ok(Array.isArray(listAck?.groups));
    assert.ok(listAck.groups.some((g) => String(g.groupId) === groupId));

    // openGroup for B (joins room + returns members)
    const openAck = await emitAck(b, "openGroup", { groupId });
    assert.equal(openAck?.success, true);
    assert.equal(openAck?.room, `group:${groupId}`);
    assert.equal(openAck?.group?.groupId, groupId);
    assert.equal(openAck?.group?.name, groupName);
    assert.equal(openAck?.group?.mlsEnabled, false);
    assert.equal(openAck?.group?.epoch, 0);
    assert.equal(openAck?.group?.cipherSuite, null);
    assert.equal(openAck?.membership?.leafIndex, 1);
    assert.ok(Array.isArray(openAck?.members));
    assert.ok(openAck.members.some((m) => String(m.userId) === userA.id && m.leafIndex === 0 && m.status === "active"));
    assert.ok(openAck.members.some((m) => String(m.userId) === userB.id && m.leafIndex === 1 && m.status === "active"));
    assert.ok(openAck.members.some((m) => String(m.userId) === userC.id && m.leafIndex === 2 && m.status === "active"));

    // Send group message from A.
    // - B is in the room, should receive via room broadcast.
    // - C is online but NOT in the room (hasn't opened the group), should receive via direct notify fallback.
    const bMsgP = once(b, "newGroupMessage");
    const cMsgP = once(c, "newGroupMessage");

    const sendAck1 = await emitAck(a, "sendGroupMessage", {
      groupId,
      payload: "hello-group-1",
      nonce: "n1",
      messageType: "text",
    });
    assert.equal(sendAck1?.success, true);
    assert.equal(sendAck1?.seq, 0);

    const [bMsg] = await bMsgP;
    const [cMsg] = await cMsgP;
    assert.equal(String(bMsg.groupId), groupId);
    assert.equal(String(cMsg.groupId), groupId);
    assert.equal(bMsg.seq, 0);
    assert.equal(cMsg.seq, 0);
    assert.equal(bMsg.payload, "hello-group-1");
    assert.equal(cMsg.payload, "hello-group-1");

    const saved1 = await Message.findOne({ conversationType: "group", groupId, seq: 0 }).lean();
    assert.ok(saved1);

    // Add member D by admin A.
    const bMemberAddedP = once(b, "groupMemberAdded");
    const dGroupAddedP = once(d, "groupAdded");

    const addAck = await emitAck(a, "addGroupMember", { groupId, memberId: userD.id });
    assert.equal(addAck?.success, true);

    const [dAddedPayload] = await dGroupAddedP;
    assert.equal(String(dAddedPayload.groupId), groupId);
    assert.equal(dAddedPayload.name, groupName);

    const [memberAddedEvt] = await bMemberAddedP;
    assert.equal(String(memberAddedEvt.groupId), groupId);
    assert.equal(String(memberAddedEvt.memberId), userD.id);

    const addedMember = await GroupMember().findOne({ groupId, userId: userD.id }).lean();
    assert.ok(addedMember);
    assert.equal(addedMember.leafIndex, 3);
    assert.equal(addedMember.status, "active");

    const welcomePayload = {
      groupId,
      epoch: 0,
      cipherSuite: "Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256",
      roster: [
        { userId: userA.id, username: userA.username, leafIndex: 0 },
        { userId: userB.id, username: userB.username, leafIndex: 1 },
        { userId: userC.id, username: userC.username, leafIndex: 2 },
        { userId: userD.id, username: userD.username, leafIndex: 3 },
      ],
      recipientUserId: userD.id,
      recipientLeafIndex: 3,
      groupKeyB64: "welcome-group-key",
    };

    const dWelcomeP = once(d, "groupWelcome");
    const welcomeAck = await emitAck(a, "sendGroupWelcome", {
      groupId,
      recipientUserId: userD.id,
      welcome: welcomePayload,
    });
    assert.equal(welcomeAck?.success, true);

    const [dWelcomeEvt] = await dWelcomeP;
    assert.equal(String(dWelcomeEvt.groupId), groupId);
    assert.deepEqual(dWelcomeEvt.welcome, welcomePayload);

    const welcomeByNonMemberAck = await emitAck(e, "sendGroupWelcome", {
      groupId,
      recipientUserId: userD.id,
      welcome: welcomePayload,
    });
    assert.equal(welcomeByNonMemberAck?.success, false);
    assert.equal(welcomeByNonMemberAck?.error, "forbidden");

    const welcomeToNonMemberAck = await emitAck(a, "sendGroupWelcome", {
      groupId,
      recipientUserId: userE.id,
      welcome: {
        ...welcomePayload,
        recipientUserId: userE.id,
        recipientLeafIndex: 4,
      },
    });
    assert.equal(welcomeToNonMemberAck?.success, false);
    assert.equal(welcomeToNonMemberAck?.error, "Recipient is not a member of the group");

    const mlsGroupName = `MLS Group ${ts}`;
    const bMlsAddedP = once(b, "groupAdded");
    const createMlsAck = await emitAck(a, "createGroup", {
      name: mlsGroupName,
      memberIds: [userB.id],
      mlsEnabled: true,
      cipherSuite: "Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256",
    });
    assert.equal(createMlsAck?.success, true);
    assert.equal(createMlsAck?.group?.mlsEnabled, true);
    assert.equal(createMlsAck?.group?.epoch, 0);
    assert.equal(createMlsAck?.group?.cipherSuite, "Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256");

    const mlsGroupId = String(createMlsAck.group.groupId);
    createdGroupIds.push(mlsGroupId);
    await bMlsAddedP;

    const openMlsAAck = await emitAck(a, "openGroup", { groupId: mlsGroupId });
    const openMlsBAck = await emitAck(b, "openGroup", { groupId: mlsGroupId });
    assert.equal(openMlsAAck?.success, true);
    assert.equal(openMlsBAck?.success, true);

    const dMlsGroupAddedP = once(d, "groupAdded");
    const addMlsAck = await emitAck(a, "addGroupMember", { groupId: mlsGroupId, memberId: userD.id });
    assert.equal(addMlsAck?.success, true);

    await dMlsGroupAddedP;

    const explicitCommit = {
      groupId: mlsGroupId,
      epoch: 1,
      type: "update",
      senderLeafIndex: 0,
      roster: [
        { userId: userA.id, username: userA.username, leafIndex: 0 },
        { userId: userB.id, username: userB.username, leafIndex: 1 },
        { userId: userD.id, username: userD.username, leafIndex: 2 },
      ],
      nextGroupKeyB64: "explicit-commit-group-key",
    };
    const welcomePayloadMls = {
      groupId: mlsGroupId,
      epoch: 1,
      cipherSuite: "Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256",
      roster: explicitCommit.roster,
      recipientUserId: userD.id,
      recipientLeafIndex: 2,
      groupKeyB64: "welcome-group-key-mls",
    };
    const dExplicitWelcomeP = once(d, "groupWelcome");
    const sendMlsWelcomeAck = await emitAck(a, "sendGroupWelcome", {
      groupId: mlsGroupId,
      recipientUserId: userD.id,
      welcome: welcomePayloadMls,
    });
    assert.equal(sendMlsWelcomeAck?.success, true);
    assert.equal(sendMlsWelcomeAck?.delivered, true);
    assert.deepEqual((await dExplicitWelcomeP)[0].welcome, welcomePayloadMls);

    const storedWelcome = await Message.findOne({
      conversationType: "group",
      groupId: mlsGroupId,
      contentType: "welcome",
      targetUserId: userD.id,
    }).lean();
    assert.ok(storedWelcome);
    assert.equal(storedWelcome.epoch, 1);
    assert.equal(storedWelcome.senderLeafIndex, 0);
    assert.deepEqual(JSON.parse(storedWelcome.payload), welcomePayloadMls);

    const dWelcomeHistoryAck = await emitAck(d, "fetchGroupMessages", { groupId: mlsGroupId, limit: 20 });
    assert.equal(dWelcomeHistoryAck?.success, true);
    assert.ok(dWelcomeHistoryAck.messages.some((message) => message.contentType === "welcome"));

    const bWelcomeHistoryAck = await emitAck(b, "fetchGroupMessages", { groupId: mlsGroupId, limit: 20 });
    assert.equal(bWelcomeHistoryAck?.success, true);
    assert.ok(bWelcomeHistoryAck.messages.every((message) => message.contentType !== "welcome"));

    const aExplicitCommitP = once(a, "groupCommit");
    const bExplicitCommitP = once(b, "groupCommit");
    const dExplicitCommitP = once(d, "groupCommit");
    const sendCommitAck = await emitAck(a, "sendGroupCommit", {
      groupId: mlsGroupId,
      commit: explicitCommit,
    });
    assert.equal(sendCommitAck?.success, true);
    assert.equal(sendCommitAck?.delivered, 3);
    assert.deepEqual((await aExplicitCommitP)[0].commit, explicitCommit);
    assert.deepEqual((await bExplicitCommitP)[0].commit, explicitCommit);
    assert.deepEqual((await dExplicitCommitP)[0].commit, explicitCommit);

    const storedCommit = await Message.findOne({
      conversationType: "group",
      groupId: mlsGroupId,
      contentType: "commit",
      epoch: 1,
    }).lean();
    assert.ok(storedCommit);
    assert.equal(storedCommit.senderLeafIndex, 0);
    assert.deepEqual(JSON.parse(storedCommit.payload), explicitCommit);

    const openAfterCommitAck = await emitAck(a, "openGroup", { groupId: mlsGroupId });
    assert.equal(openAfterCommitAck?.success, true);
    assert.equal(openAfterCommitAck?.group?.epoch, 1);

    const dCommitHistoryAck = await emitAck(d, "fetchGroupMessages", { groupId: mlsGroupId, limit: 20 });
    assert.equal(dCommitHistoryAck?.success, true);
    assert.ok(dCommitHistoryAck.messages.some((message) => message.contentType === "commit"));

    const sendCommitByNonMemberAck = await emitAck(e, "sendGroupCommit", {
      groupId: mlsGroupId,
      commit: explicitCommit,
    });
    assert.equal(sendCommitByNonMemberAck?.success, false);
    assert.equal(sendCommitByNonMemberAck?.error, "forbidden");

    const sendCommitWrongGroupAck = await emitAck(a, "sendGroupCommit", {
      groupId: mlsGroupId,
      commit: { ...explicitCommit, groupId: "wrong-group" },
    });
    assert.equal(sendCommitWrongGroupAck?.success, false);
    assert.equal(sendCommitWrongGroupAck?.error, "Commit groupId mismatch");
    const bMlsRemovedP = once(b, "groupRemoved");
    const removeMlsAck = await emitAck(a, "removeGroupMember", { groupId: mlsGroupId, memberId: userB.id });
    assert.equal(removeMlsAck?.success, true);
    const [bMlsRemovedEvt] = await bMlsRemovedP;
    assert.equal(String(bMlsRemovedEvt.groupId), mlsGroupId);

    // BUG REPRO: after admin-removal in an MLS group, openGroup must NOT return the removed member.
    const openAfterMlsRemoveAck = await emitAck(a, "openGroup", { groupId: mlsGroupId });
    assert.equal(openAfterMlsRemoveAck?.success, true);
    const stillListed = (openAfterMlsRemoveAck?.members ?? []).some(
      (m) => String(m.userId) === String(userB.id)
    );
    assert.equal(stillListed, false, "removed MLS member must not appear in openGroup members");

    const shadowDeviceUserId = `${userB.id}_x1`;
    createdUserIds.push(shadowDeviceUserId);
    await Promise.all([
      User.create({
        id: shadowDeviceUserId,
        username: `gb_device_${ts}`,
        hashedPassword: "x",
        publicIdentityKeyX25519: "x",
        publicIdentityKeyEd25519: "x",
        signedPreKey: "x",
        signature: "x",
      }),
      User.updateOne({ id: userB.id }, { $addToSet: { devices: shadowDeviceUserId } }),
      Device().create({
        deviceId: `device-${shadowDeviceUserId}`,
        parentUserId: userB.id,
        deviceUserId: shadowDeviceUserId,
      }),
    ]);

    const shadowGroupAck = await emitAck(a, "createGroup", {
      name: `MLS Shadow ${ts}`,
      memberIds: [userB.id],
      mlsEnabled: true,
      cipherSuite: "Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256",
    });
    assert.equal(shadowGroupAck?.success, true);
    const shadowGroupId = String(shadowGroupAck.group.groupId);
    createdGroupIds.push(shadowGroupId);

    await GroupMember().updateOne(
      { groupId: shadowGroupId, userId: userB.id },
      { $set: { status: "removed" } }
    );
    await GroupMember().create({
      groupId: shadowGroupId,
      userId: shadowDeviceUserId,
      role: "member",
      joinedAt: new Date(),
      leafIndex: 7,
      status: "active",
    });

    bDevice = await connectAuthed({ port, id: shadowDeviceUserId, username: `gb_device_${ts}` });
    const shadowSendAck = await emitAck(bDevice, "sendGroupMessage", {
      groupId: shadowGroupId,
      messageType: "text",
      contentType: "application",
      headerB64: "header",
      ciphertextB64: "ciphertext",
      epoch: 0,
      senderLeafIndex: 7,
    });
    assert.equal(
      shadowSendAck?.success,
      true,
      "active re-add/device membership must not be shadowed by a removed parent row"
    );

    // Non-admin cannot add members.
    const addByMemberAck = await emitAck(b, "addGroupMember", { groupId, memberId: `X-${ts}` });
    assert.equal(addByMemberAck?.success, false);

    // Remove member C by admin A.
    const bMemberRemovedP = once(b, "groupMemberRemoved");
    const cRemovedP = once(c, "groupRemoved");

    const rmAck = await emitAck(a, "removeGroupMember", { groupId, memberId: userC.id });
    assert.equal(rmAck?.success, true);

    const [cRemovedEvt] = await cRemovedP;
    assert.equal(String(cRemovedEvt.groupId), groupId);

    const [bRemovedEvt] = await bMemberRemovedP;
    assert.equal(String(bRemovedEvt.groupId), groupId);
    assert.equal(String(bRemovedEvt.memberId), userC.id);

    // Removed member C can no longer open the group
    const openCAck = await emitAck(c, "openGroup", { groupId });
    assert.equal(openCAck?.success, false);

    // Back-compat: member D can fetch metadata via inbound groupAdded
    const dInfoAck = await emitAck(d, "groupAdded", { groupId });
    assert.equal(dInfoAck?.success, true);
    assert.equal(String(dInfoAck?.group?.groupId), groupId);
    assert.equal(dInfoAck?.group?.mlsEnabled, false);
    assert.equal(dInfoAck?.group?.epoch, 0);
    assert.equal(dInfoAck?.group?.cipherSuite, null);
    assert.equal(dInfoAck?.membership?.leafIndex, 3);
    assert.ok(Array.isArray(dInfoAck?.members));
    assert.ok(dInfoAck.members.some((m) => String(m.userId) === userD.id && m.leafIndex === 3 && m.status === "active"));

    // Non-member E cannot fetch metadata via inbound groupAdded
    const eInfoAck = await emitAck(e, "groupAdded", { groupId });
    assert.equal(eInfoAck?.success, false);
  } finally {
    for (const client of [a, b, c, d, e, bDevice]) {
      try {
        if (client) client.disconnect();
      } catch {}
    }

    // Best-effort cleanup by group id(s) created in this test.
    await Promise.allSettled([
      Message.deleteMany({ conversationType: "group", groupId: { $in: createdGroupIds } }),
      GroupMember().deleteMany({ groupId: { $in: createdGroupIds } }),
      GroupSequence().deleteMany({ groupId: { $in: createdGroupIds } }),
      Group().deleteMany({ groupId: { $in: createdGroupIds } }),
      Device().deleteMany({ parentUserId: { $in: createdUserIds } }),
      User.deleteMany({ id: { $in: createdUserIds } }),
    ]);

    await new Promise((resolve) => server.close(resolve));
    await mongoose.disconnect();
  }
});
