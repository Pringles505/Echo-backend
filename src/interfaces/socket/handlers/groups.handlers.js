/**
 * Socket event handlers for group messaging and MLS (Messaging Layer Security) events.
 * Implements group creation, membership management, welcome message distribution,
 * and MLS commit/proposal processing.
 * @module interfaces/socket/handlers/groups
 */

const { customAlphabet } = require('nanoid');

/**
 * @typedef {object} CreateGroupPayload
 * @property {string} groupName - Name of the group to create
 * @property {Array<string>} memberIds - Array of user IDs to add as members
 */

/**
 * @typedef {object} GroupWelcomePayload
 * @property {string} groupId - Group ID
 * @property {Array} welcome - MLS welcome message
 * @property {string} [targetUserId] - Optional recipient user ID
 */

/**
 * @typedef {object} GroupMessagePayload
 * @property {string} groupId - Target group ID
 * @property {string} payload - Encrypted message (base64)
 * @property {number} messageNumber - Message sequence number
 * @property {number} sendingNumber - Signal Protocol sending number
 * @property {number} previousSendingNumber - Previous sending number
 * @property {string} publicEphemeralKey - Ephemeral key for decryption
 * @property {number} [spkId] - Signed Pre-Key ID
 * @property {number} [opkId] - One-Time Pre-Key ID
 */

/**
 * Registers Socket.IO handlers for group messaging and MLS operations.
 * Manages group lifecycle, membership, message distribution, and MLS integration.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {import('mongoose').Model} deps.Message - Message model
 * @param {import('mongoose').Model} deps.User - User model
 * @param {import('mongoose').Model} deps.Group - Group model
 * @param {import('mongoose').Model} deps.GroupMember - Group member model
 * @param {import('mongoose').Model} deps.GroupSequence - Group sequence model
 * @param {import('mongoose').Model} deps.KeyPackage - Key package model (for MLS)
 * @param {function} deps.ensureGroupSequence - Ensure group sequence document exists
 */
function registerGroupsSocketHandlers(deps) {
  const {
    socket,
    io,
    Message,
    User,
    Device,
    Group,
    GroupMember,
    GroupSequence,
    KeyPackage,
    ensureGroupSequence,
  } = deps;

  // Resolve a socket user id to its parent account id.
  //
  // After the per-device migration, every device of an account has its own row
  // in `Device` (with `parentUserId`) and the parent's `User.devices` array
  // lists each `deviceUserId`. `upsertDeviceUser` ALSO inserts a separate `User`
  // doc with `id === deviceUserId` (so device profile lookups work) — which
  // means a naive `User.findOne({ id: <deviceUserId> })` is ambiguous: it would
  // happily return that device-shaped User and we'd treat the device as its
  // own account, splitting GroupMember rows between parent-keyed and
  // device-keyed identifiers.
  //
  // Lookup order:
  //   1) Device.deviceUserId → parentUserId   (authoritative)
  //   2) User.devices contains the id          (covers legacy / no-Device-row)
  //   3) Direct User.id match                  (the id IS a parent account)
  const resolveAccountUserId = async (authedUserId) => {
    const authedUserIdStr = String(authedUserId ?? '');
    if (!authedUserIdStr) {
      return { userId: '', resolvedVia: 'empty', deviceUserIds: [] };
    }

    if (Device) {
      const device = await Device.findOne(
        { deviceUserId: authedUserIdStr },
        { parentUserId: 1 }
      ).lean();
      if (device?.parentUserId) {
        const parent = await User.findOne(
          { id: String(device.parentUserId) },
          { id: 1, devices: 1 }
        ).lean();
        return {
          userId: String(device.parentUserId),
          resolvedVia: 'device',
          deviceUserIds: parent?.devices ? parent.devices.map(String) : [],
        };
      }
    }

    const parentByDevicesArray = await User.findOne(
      { devices: authedUserIdStr },
      { id: 1, devices: 1 }
    ).lean();
    if (parentByDevicesArray?.id) {
      return {
        userId: String(parentByDevicesArray.id),
        resolvedVia: 'deviceUserId',
        deviceUserIds: (parentByDevicesArray.devices ?? []).map(String),
      };
    }

    const directUser = await User.findOne(
      { id: authedUserIdStr },
      { id: 1, devices: 1 }
    ).lean();
    if (directUser?.id) {
      return {
        userId: authedUserIdStr,
        resolvedVia: 'direct',
        deviceUserIds: (directUser.devices ?? []).map(String),
      };
    }

    return { userId: authedUserIdStr, resolvedVia: 'none', deviceUserIds: [] };
  };

  // Collect every socket room id that should receive events for an account:
  // parent user id plus each sibling deviceUserId.
  const collectAccountDeliveryIds = async (userOrDeviceId) => {
    const account = await resolveAccountUserId(userOrDeviceId);
    const ids = new Set();
    const raw = String(userOrDeviceId ?? '');
    if (raw) ids.add(raw);
    if (account.userId) ids.add(String(account.userId));
    for (const did of account.deviceUserIds ?? []) {
      if (did) ids.add(String(did));
    }
    return { account, ids: Array.from(ids) };
  };

  // Find a (groupId, userId) GroupMember row by trying every identifier the
  // socket might possibly be keyed under: the resolved parent account id, the
  // raw JWT id, and each known sibling deviceUserId. Old groups created before
  // the auth-resolution fix may have rows keyed by deviceUserId; new groups
  // are parent-keyed. This lookup matches both without forcing a migration.
  const resolveGroupUserId = async (groupId, authedUserId) => {
    const account = await resolveAccountUserId(authedUserId);
    const authedUserIdStr = String(authedUserId ?? '');

    const candidateIds = new Set();
    if (account.userId) candidateIds.add(account.userId);
    if (authedUserIdStr) candidateIds.add(authedUserIdStr);
    for (const did of account.deviceUserIds ?? []) {
      if (did) candidateIds.add(did);
    }

    if (candidateIds.size === 0) {
      return { userId: account.userId, membership: null, resolvedVia: account.resolvedVia };
    }

    const memberships = await GroupMember.find({
      groupId,
      userId: { $in: Array.from(candidateIds) },
    }).lean();

    // Prefer an active parent-keyed row (the new canonical layout), then any
    // active sibling/legacy row. A removed parent tombstone must not shadow a
    // fresh active re-add row keyed by another account identifier.
    const parentRows = memberships.filter((m) => String(m.userId) === String(account.userId));
    const activeParent = parentRows.find((m) => m.status !== 'removed');
    const activeFallback = memberships.find((m) => m.status !== 'removed');
    const removedParent = parentRows.find((m) => m.status === 'removed') ?? parentRows[0] ?? null;
    const chosen = activeParent ?? activeFallback ?? removedParent ?? memberships[0] ?? null;

    return {
      userId: account.userId || authedUserIdStr,
      membership: chosen ?? null,
      resolvedVia: chosen
        ? (String(chosen.userId) === String(account.userId) ? 'parent' : 'sibling')
        : account.resolvedVia,
    };
  };

  const emitEventToGroupMembers = async ({ groupId, eventName, payload, excludeUserIds = [] }) => {
    const groupIdStr = String(groupId ?? '');
    const exclude = new Set(excludeUserIds.map((userId) => String(userId ?? '')).filter(Boolean));
    const members = await GroupMember.find(
      { groupId: groupIdStr, status: { $ne: 'removed' } },
      { userId: 1 }
    ).lean();

    const deliveredRooms = new Set();
    for (const member of members) {
      const memberId = String(member?.userId ?? '');
      if (!memberId) continue;
      const { ids } = await collectAccountDeliveryIds(memberId);
      for (const id of ids) {
        if (!id || exclude.has(id) || deliveredRooms.has(id)) continue;
        io.to(id).emit(eventName, payload);
        deliveredRooms.add(id);
      }
    }
    return deliveredRooms.size;
  };

  const filterReachableKeyPackages = async (userId, packages) => {
    if (!Device || !Array.isArray(packages) || packages.length === 0) return packages;

    const activeDevices = await Device.find(
      { parentUserId: String(userId ?? ''), isRevoked: false },
      { deviceId: 1 }
    ).lean();
    const activeClientIds = new Set(
      activeDevices
        .map((device) => String(device?.deviceId ?? ''))
        .filter((deviceId) => deviceId.length > 0)
    );

    // Some tests and legacy accounts have KeyPackages before Device rows existed.
    // In that case keep the historical behavior instead of hiding all packages.
    if (activeClientIds.size === 0) return packages;

    return packages.filter((kp) => {
      const clientId = kp?.clientId == null ? null : String(kp.clientId);
      return clientId === null || activeClientIds.has(clientId);
    });
  };

  const allocateNextGroupSequence = async (groupId) => {
    const groupIdStr = String(groupId ?? '');
    await ensureGroupSequence(groupIdStr);

    const updated = await GroupSequence.findOneAndUpdate(
      { groupId: groupIdStr },
      { $inc: { lastSequenceNumber: 1 }, $set: { updatedAt: new Date() } },
      { new: true }
    );

    if (!updated) throw new Error(`Failed to allocate group sequence for ${groupIdStr}`);
    return updated.lastSequenceNumber;
  };

  const persistGroupArtifactMessage = async ({
    groupId,
    senderUserId,
    senderUsername,
    targetUserId = null,
    epoch = null,
    senderLeafIndex = null,
    contentType,
    artifact,
  }) => {
    const groupIdStr = String(groupId ?? '');
    const seq = await allocateNextGroupSequence(groupIdStr);

    const message = new Message({
      payload: JSON.stringify(artifact),
      nonce: `artifact:${contentType}:${seq}`,
      userId: String(senderUserId ?? ''),
      targetUserId: targetUserId ? String(targetUserId) : null,
      conversationKey: null,
      username: senderUsername,
      seenStatus: false,
      messageNumber: null,
      sendingNumber: null,
      previousSendingNumber: null,
      publicEphemeralKey: null,
      spkId: null,
      opkId: null,
      messageType: 'text',
      conversationType: 'group',
      groupId: groupIdStr,
      seq,
      epoch: Number.isInteger(epoch) ? epoch : null,
      senderLeafIndex: Number.isInteger(senderLeafIndex) ? senderLeafIndex : null,
      contentType,
      headerB64: null,
      ciphertextB64: null,
    });

    await message.save();
    return { message, seq };
  };

  const fetchGroupInfoForMember = async ({ groupId, authedUserId }) => {
    const groupIdStr = String(groupId ?? '');
    const authedUserIdStr = String(authedUserId ?? '');
    if (!groupIdStr) return { ok: false, error: 'Invalid groupId' };
    if (!authedUserIdStr) return { ok: false, error: 'unauthorized' };

    const [group, resolved] = await Promise.all([
      Group.findOne({ groupId: groupIdStr }).lean(),
      resolveGroupUserId(groupIdStr, authedUserIdStr),
    ]);
    const membership = resolved.membership;

    if (!group) return { ok: false, error: 'Group not found' };
    if (!membership) return { ok: false, error: 'forbidden' };
    if (membership.status === 'removed') return { ok: false, error: 'removed' };

    const members = await GroupMember.find({ groupId: groupIdStr, status: { $ne: 'removed' } }).lean();
    const memberIds = members.map((m) => String(m.userId));
    const profiles = await User.find({ id: { $in: memberIds } }, { id: 1, username: 1, profilePicture: 1 }).lean();
    const profileById = new Map(profiles.map((p) => [String(p.id), p]));

    return {
      ok: true,
      group: {
        groupId: group.groupId,
        name: group.name,
        createdBy: group.createdBy,
        createdAt: group.createdAt,
        mlsEnabled: group.mlsEnabled,
        epoch: group.epoch,
        cipherSuite: group.cipherSuite,
      },
      membership: {
        role: membership.role,
        joinedAt: membership.joinedAt,
        leafIndex: membership.leafIndex,
        status: membership.status,
      },
      members: members.map((m) => {
        const uid = String(m.userId);
        const p = profileById.get(uid);
        return {
          userId: uid,
          role: m.role,
          joinedAt: m.joinedAt,
          username: p?.username ?? null,
          profilePicture: p?.profilePicture ?? null,
          leafIndex: m.leafIndex,
          status: m.status,
        };
      }),
    };
  };

  socket.on('createGroup', async ({ name, memberIds, mlsEnabled, cipherSuite }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });
    if (!name || typeof name !== 'string' || name.trim().length === 0) return cb?.({ success: false, error: 'Group name is required' });
    if (!Array.isArray(memberIds) || memberIds.length === 0) return cb?.({ success: false, error: 'At least one member is required' });

    const wantsMls = mlsEnabled === true;
    const normalizedCipherSuite = wantsMls
      ? (typeof cipherSuite === 'string' && cipherSuite.trim().length > 0 ? cipherSuite.trim() : 'Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256')
      : null;

    const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
    const emitToAccount = async (targetUserId, eventName, payload) => {
      const { ids } = await collectAccountDeliveryIds(targetUserId);
      for (const id of ids) io.to(id).emit(eventName, payload);
    };

    const nowIso = new Date().toISOString();
    let groupId = null;

    try {
      const account = await resolveAccountUserId(authedUserId);
      const authedUserIdStr = account.userId;
      const creatorProfile = await User.findOne({ id: authedUserIdStr }, { username: 1 }).lean();
      const creatorUsername = creatorProfile?.username ?? null;
      const normalizedMemberIds = [...new Set(memberIds.map((m) => String(m ?? '')).filter(Boolean))].filter((id) => id !== authedUserIdStr);
      if (normalizedMemberIds.length === 0) return cb?.({ success: false, error: 'At least one member is required' });

      for (let attempt = 0; attempt < 5; attempt++) {
        const candidate = nanoid();
        try {
          await Group.create({
            groupId: candidate,
            name,
            createdBy: authedUserIdStr,
            createdAt: new Date(),
            mlsEnabled: wantsMls,
            epoch: 0,
            cipherSuite: normalizedCipherSuite,
          });
          groupId = candidate;
          break;
        } catch (err) {
          if (err?.code === 11000) continue;
          throw err;
        }
      }

      if (!groupId) return cb?.({ success: false, error: 'Failed to allocate group id' });

      await ensureGroupSequence(groupId);

      await GroupMember.create({
        groupId,
        userId: authedUserIdStr,
        role: 'admin',
        joinedAt: new Date(),
        leafIndex: 0,
        status: 'active',
      });

      for (const [index, memberId] of normalizedMemberIds.entries()) {
        await GroupMember.create({
          groupId,
          userId: memberId,
          role: 'member',
          joinedAt: new Date(),
          leafIndex: index + 1,
          status: 'active',
        });
        await emitToAccount(memberId, 'groupAdded', {
          groupId,
          name,
          addedByUserId: authedUserIdStr,
          addedByUsername: creatorUsername,
          role: 'member',
          at: nowIso,
        });
      }

      await emitToAccount(authedUserIdStr, 'groupAdded', {
        groupId,
        name,
        addedByUserId: authedUserIdStr,
        addedByUsername: creatorUsername,
        role: 'admin',
        at: nowIso,
      });
      cb?.({
        success: true,
        group: { groupId, name, mlsEnabled: wantsMls, epoch: 0, cipherSuite: normalizedCipherSuite },
        members: [
          { userId: authedUserIdStr, leafIndex: 0 },
          ...normalizedMemberIds.map((id, index) => ({ userId: id, leafIndex: index + 1 })),
        ],
      });
    } catch (err) {
      console.error('Error creating group:', err);
      if (groupId) {
        await Promise.allSettled([
          Group.deleteOne({ groupId }),
          GroupSequence.deleteOne({ groupId }),
          GroupMember.deleteMany({ groupId }),
        ]);
      }
      cb?.({ success: false, error: 'Error creating group' });
    }
  });

  socket.on('groupAdded', async ({ groupId }, cb) => {
    const authedUserId = socket.user?.id;
    try {
      const res = await fetchGroupInfoForMember({ groupId, authedUserId });
      if (!res.ok) return cb?.({ success: false, error: res.error });
      return cb?.({ success: true, ...res });
    } catch (err) {
      console.error('Error fetching group info:', err);
      return cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('listMyGroups', async (_data, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const account = await resolveAccountUserId(authedUserId);
      const candidateIds = new Set();
      if (account.userId) candidateIds.add(account.userId);
      if (authedUserId) candidateIds.add(String(authedUserId));
      for (const did of account.deviceUserIds ?? []) {
        if (did) candidateIds.add(did);
      }
      // Match rows keyed by either the parent or any sibling deviceUserId so
      // legacy/pre-resolution groups still show up alongside parent-keyed ones.
      const memberships = await GroupMember.find({
        userId: { $in: Array.from(candidateIds) },
        status: { $ne: 'removed' },
      }).lean();
      // Dedupe by groupId — prefer the parent-keyed row so the leafIndex/role
      // reported to the client matches the canonical row.
      const byGroupId = new Map();
      for (const m of memberships) {
        const gid = String(m.groupId ?? '');
        if (!gid) continue;
        const existing = byGroupId.get(gid);
        if (!existing || String(m.userId) === String(account.userId)) {
          byGroupId.set(gid, m);
        }
      }
      const dedupedMemberships = Array.from(byGroupId.values());
      const groupIds = dedupedMemberships.map((m) => String(m.groupId)).filter(Boolean);
      const groups = await Group.find({ groupId: { $in: groupIds } }).lean();
      const groupById = new Map(groups.map((g) => [String(g.groupId), g]));
      const result = dedupedMemberships.map((m) => {
        const g = groupById.get(String(m.groupId));
        if (!g) return null;
        return {
          groupId: g.groupId,
          name: g.name,
          role: m.role,
          joinedAt: m.joinedAt,
          createdAt: g.createdAt,
          createdBy: g.createdBy,
          mlsEnabled: g.mlsEnabled,
          epoch: g.epoch,
          cipherSuite: g.cipherSuite,
          leafIndex: m.leafIndex,
          status: m.status,
        };
      }).filter(Boolean);
      cb?.({ success: true, groups: result });
    } catch (err) {
      console.error('Error listing groups:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('openGroup', async ({ groupId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr) return cb?.({ success: false, error: 'Invalid groupId' });

    try {
      const res = await fetchGroupInfoForMember({ groupId: groupIdStr, authedUserId });
      if (!res.ok) return cb?.({ success: false, error: res.error });
      const room = `group:${groupIdStr}`;
      socket.join(room);
      cb?.({ success: true, room, ...res });
    } catch (err) {
      console.error('Error opening group:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('fetchGroupMessages', async ({ groupId, beforeSeq, limit }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr) return cb?.({ success: false, error: 'Invalid groupId' });

    try {
      const resolved = await resolveGroupUserId(groupIdStr, authedUserId);
      const membership = resolved.membership;
      if (!membership || membership.status === 'removed') {
        return cb?.({ success: false, error: membership?.status === 'removed' ? 'removed' : 'forbidden' });
      }

      const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 200));
      const query = {
        conversationType: 'group',
        groupId: groupIdStr,
        $or: [{ targetUserId: null }, { targetUserId: resolved.userId }],
      };
      const before = Number(beforeSeq);
      if (Number.isFinite(before)) query.seq = { $lt: before };

      const batchDesc = await Message.find(query).sort({ seq: -1 }).limit(safeLimit).lean();
      const batch = batchDesc.reverse();
      const nextBeforeSeq = batch.length > 0 ? batch[0].seq : null;

      cb?.({ success: true, messages: batch, nextBeforeSeq });
    } catch (err) {
      console.error('Error fetching group messages:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('addGroupMember', async ({ groupId, memberId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const memberIdStr = String(memberId ?? '');
    if (!groupIdStr || !memberIdStr) return cb?.({ success: false, error: 'Missing required fields' });

    try {
      const [group, resolved] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
      ]);
      const callerMembership = resolved.membership;
      const sender = await User.findOne({ id: resolved.userId }, { username: 1 }).lean();
      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership || callerMembership.status === 'removed' || callerMembership.role !== 'admin') {
        return cb?.({ success: false, error: 'forbidden' });
      }

      const addTarget = await collectAccountDeliveryIds(memberIdStr);
      const canonicalMemberId = String(addTarget.account.userId || memberIdStr);
      const addTargetIds = addTarget.ids.length > 0 ? addTarget.ids : [memberIdStr];

      // For MLS groups, membership DB changes are driven by confirmMlsCommit after the
      // cryptographic commit has been distributed and applied. addGroupMember only
      // pre-registers the member with status 'invited' so the server knows to deliver
      // the Welcome; the status becomes 'active' via confirmMlsCommit.
      // Only an *active/invited* row blocks re-adding — a removed-status row is a
      // tombstone and should be cleaned up so the new row can take its place.
      const existing = await GroupMember.findOne({
        groupId: groupIdStr,
        userId: { $in: addTargetIds },
        status: { $ne: 'removed' },
      }).lean();
      if (existing) return cb?.({ success: false, error: 'already_member' });
      await GroupMember.deleteMany({
        groupId: groupIdStr,
        userId: { $in: addTargetIds },
        status: 'removed',
      });

      const existingMembers = await GroupMember.find(
        { groupId: groupIdStr, status: { $ne: 'removed' } },
        { leafIndex: 1 }
      ).lean();
      const maxLeafIndex = existingMembers.reduce((max, member) => (Number.isInteger(member.leafIndex) && member.leafIndex > max ? member.leafIndex : max), -1);
      const nextLeafIndex = maxLeafIndex + 1;

      const initialStatus = group.mlsEnabled ? 'invited' : 'active';

      await GroupMember.create({
        groupId: groupIdStr,
        userId: canonicalMemberId,
        role: 'member',
        joinedAt: new Date(),
        leafIndex: nextLeafIndex,
        status: initialStatus,
      });

      const nowIso = new Date().toISOString();
      const room = `group:${groupIdStr}`;
      for (const deliveryId of addTargetIds) {
        io.to(deliveryId).emit('groupAdded', {
          groupId: groupIdStr,
          name: group.name,
          addedByUserId: resolved.userId,
          addedByUsername: sender?.username ?? null,
          role: 'member',
          at: nowIso,
        });
      }

      io.to(room).emit('groupMemberAdded', {
        groupId: groupIdStr,
        memberId: canonicalMemberId,
        addedByUserId: resolved.userId,
        addedByUsername: sender?.username ?? null,
        role: 'member',
        at: nowIso,
      });

      cb?.({ success: true });
    } catch (err) {
      console.error('Error adding group member:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('removeGroupMember', async ({ groupId, memberId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const memberIdStr = String(memberId ?? '');
    if (!groupIdStr || !memberIdStr) return cb?.({ success: false, error: 'Missing required fields' });

    try {
      const [group, resolved, targetCandidates] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
        collectAccountDeliveryIds(memberIdStr),
      ]);
      const callerMembership = resolved.membership;
      const remover = await User.findOne({ id: resolved.userId }, { username: 1 }).lean();
      const targetMemberships = await GroupMember.find({
        groupId: groupIdStr,
        userId: { $in: targetCandidates.ids },
      }).lean();
      const targetMembership =
        targetMemberships.find((m) => m.status !== 'removed') ?? targetMemberships[0] ?? null;
      const canonicalMemberId = String(targetCandidates.account.userId || memberIdStr);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership || callerMembership.status === 'removed') return cb?.({ success: false, error: 'forbidden' });
      if (!targetMembership || targetMembership.status === 'removed') return cb?.({ success: false, error: 'not_a_member' });

      const isSelf = resolved.userId === canonicalMemberId;
      const canRemove = isSelf || (callerMembership.role === 'admin' && (targetMembership.role !== 'admin' || isSelf));
      if (!canRemove) return cb?.({ success: false, error: 'forbidden' });

      const room = `group:${groupIdStr}`;
      const nowIso = new Date().toISOString();

      if (group.mlsEnabled && !isSelf) {
        // MLS admin-removal: mark the member as removed so subsequent openGroup
        // calls exclude them. The cryptographic remove commit is broadcast
        // separately via sendGroupCommit, which advances the epoch.
        // updateMany (not updateOne) handles any duplicate rows that may exist
        // for the same (groupId, userId) from prior partial/legacy state.
        await GroupMember.updateMany(
          { groupId: groupIdStr, userId: { $in: targetCandidates.ids } },
          { $set: { status: 'removed' } }
        );
        for (const deliveryId of targetCandidates.ids) {
          io.in(deliveryId).socketsLeave(room);
          io.to(deliveryId).emit('groupRemoved', {
            groupId: groupIdStr,
            memberId: canonicalMemberId,
            removedByUserId: resolved.userId,
            removedByUsername: remover?.username ?? null,
            groupName: group.name,
            at: nowIso,
          });
        }
        io.to(room).emit('groupMemberRemoved', {
          groupId: groupIdStr,
          memberId: canonicalMemberId,
          removedByUserId: resolved.userId,
          removedByUsername: remover?.username ?? null,
          groupName: group.name,
          at: nowIso,
        });
      } else {
        // Non-MLS groups or self-leave: complete immediately.
        await GroupMember.deleteMany({ groupId: groupIdStr, userId: { $in: targetCandidates.ids } });
        for (const deliveryId of targetCandidates.ids) {
          io.in(deliveryId).socketsLeave(room);
          io.to(deliveryId).emit('groupRemoved', {
            groupId: groupIdStr,
            memberId: canonicalMemberId,
            removedByUserId: resolved.userId,
            removedByUsername: remover?.username ?? null,
            groupName: group.name,
            at: nowIso,
          });
        }
        io.to(room).emit('groupMemberRemoved', {
          groupId: groupIdStr,
          memberId: canonicalMemberId,
          removedByUserId: resolved.userId,
          removedByUsername: remover?.username ?? null,
          groupName: group.name,
          at: nowIso,
        });
      }

      cb?.({ success: true });
    } catch (err) {
      console.error('Error removing group member:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('sendGroupMessage', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const ack = (payload) => {
      if (typeof callback === 'function') callback(payload);
    };

    const {
      groupId,
      payload,
      nonce,
      sendingNumber,
      previousSendingNumber,
      publicEphemeralKey,
      spkId,
      opkId,
      messageType,
      contentType,
      headerB64,
      ciphertextB64,
      // Item #3: encrypted sender identity — preferred over plaintext headerB64
      encryptedSenderDataB64,
      epoch,
      senderLeafIndex,
    } = data ?? {};

    const groupIdStr = String(groupId ?? '');

    try {
      const [group, resolved] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
      ]);
      const sender = await User.findOne({ id: resolved.userId });
      const membership = resolved.membership;
      if (!sender) return ack({ success: false, error: 'Sender not found' });
      if (!group) return ack({ success: false, error: 'Group not found' });
      if (!membership || membership.status === 'removed') {
        const allRows = await GroupMember.find({ groupId: groupIdStr }, { userId: 1, status: 1, role: 1 }).lean();
        console.warn(
          '[sendGroupMessage] Forbidden:',
          JSON.stringify({
            authedUserId,
            resolvedUserId: resolved.userId,
            resolvedVia: resolved.resolvedVia,
            groupId: groupIdStr,
            membershipStatus: membership?.status ?? null,
            allGroupRows: allRows,
          })
        );
        return ack({
          success: false,
          error: 'Forbidden',
          details: !membership
            ? `No group membership for socket user ${authedUserId} (resolved ${resolved.userId} via ${resolved.resolvedVia}) in group ${groupIdStr}`
            : `Group membership for ${resolved.userId} is ${membership.status}`,
        });
      }
      if (!groupIdStr) return ack({ success: false, error: 'Missing required fields' });

      const isMlsGroup = group.mlsEnabled === true;
      if (isMlsGroup) {
        const validContentTypes = new Set(['application', 'commit', 'welcome']);
        // Item #3: accept either a plaintext headerB64 (legacy) or encryptedSenderDataB64
        const hasFraming =
          (typeof headerB64 === 'string' && headerB64.length > 0) ||
          (typeof encryptedSenderDataB64 === 'string' && encryptedSenderDataB64.length > 0);
        if (
          typeof contentType !== 'string' ||
          !validContentTypes.has(contentType) ||
          !hasFraming ||
          typeof ciphertextB64 !== 'string' ||
          ciphertextB64.length === 0 ||
          typeof epoch !== 'number' ||
          !Number.isInteger(senderLeafIndex)
        ) {
          return ack({ success: false, error: 'Missing required fields' });
        }
        const groupEpoch = Number.isInteger(group.epoch) ? group.epoch : 0;
        if (epoch !== groupEpoch) {
          return ack({
            success: false,
            error: 'Invalid message epoch',
            details: `Group epoch is ${groupEpoch}, message epoch is ${epoch}`,
          });
        }
      } else if (typeof payload !== 'string' || payload.length === 0 || typeof nonce !== 'string' || nonce.length === 0) {
        return ack({ success: false, error: 'Missing required fields' });
      }

      await ensureGroupSequence(groupIdStr);
      const updated = await GroupSequence.findOneAndUpdate(
        { groupId: groupIdStr },
        { $inc: { lastSequenceNumber: 1 }, $set: { updatedAt: new Date() } },
        { new: true }
      );
      if (!updated) return ack({ success: false, error: 'Failed to allocate sequence number' });

      const seq = updated.lastSequenceNumber;
      const message = new Message({
        payload: isMlsGroup ? null : payload,
        nonce,
        userId: resolved.userId,
        targetUserId: null,
        conversationKey: null,
        username: sender.username,
        seenStatus: false,
        messageNumber: null,
        sendingNumber,
        previousSendingNumber,
        publicEphemeralKey,
        spkId: spkId ?? null,
        opkId: opkId ?? null,
        messageType: typeof messageType === 'string' ? messageType : 'text',
        conversationType: 'group',
        groupId: groupIdStr,
        seq,
        epoch: isMlsGroup ? epoch : null,
        senderLeafIndex: isMlsGroup ? senderLeafIndex : null,
        contentType: isMlsGroup ? contentType : null,
        headerB64: isMlsGroup ? (headerB64 ?? null) : null,
        ciphertextB64: isMlsGroup ? ciphertextB64 : null,
        // Item #3: persist encrypted sender identity so receivers can use it
        encryptedSenderDataB64: isMlsGroup ? (encryptedSenderDataB64 ?? null) : null,
      });

      await message.save();
      const room = `group:${groupIdStr}`;
      const messageWithProfile = {
        ...message.toObject(),
        profileImage: sender.profilePicture || null,
        timestamp: message.createdAt,
        groupName: group?.name ?? null,
        epoch: message.epoch,
        senderLeafIndex: message.senderLeafIndex,
        contentType: message.contentType,
        headerB64: message.headerB64,
        ciphertextB64: message.ciphertextB64,
        // Item #3: forward encrypted sender identity to all recipients
        encryptedSenderDataB64: message.encryptedSenderDataB64 ?? null,
      };

      io.to(room).emit('newGroupMessage', messageWithProfile);

      const members = await GroupMember.find(
        { groupId: groupIdStr, status: { $ne: 'removed' } },
        { userId: 1 }
      ).lean();
      const notifiedRooms = new Set([room]);
      for (const m of members) {
        const memberId = String(m?.userId ?? '');
        if (!memberId) continue;
        const { ids } = await collectAccountDeliveryIds(memberId);
        for (const id of ids) {
          if (!id || notifiedRooms.has(id)) continue;
          io.to(id).except(room).emit('newGroupMessage', messageWithProfile);
          notifiedRooms.add(id);
        }
      }

      ack({ success: true, seq });
    } catch (err) {
      console.error('Error saving group message:', err);
      const details = process.env.NODE_ENV && process.env.NODE_ENV.toLowerCase() === 'production'
        ? undefined
        : (err?.message ?? String(err));
      ack({ success: false, error: 'Error saving message', details });
    }
  });

  /**
   * 'groupTyping' / 'groupStopTyping' - Relay an ephemeral typing indicator to
   * the other members of a group. Fans out to every member's per-user delivery
   * rooms (NOT just the `group:<id>` room, which a member only joins after
   * opening the group) so the conversation-list preview can show it too. The
   * typist's own rooms are excluded. Carries no message content.
   */
  socket.on('groupTyping', async ({ groupId } = {}) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !groupId) return;
    try {
      const { userId: accountId } = await resolveAccountUserId(authedUserId);
      const [user, { ids: senderRooms }] = await Promise.all([
        User.findOne({ id: accountId }, { username: 1 }).lean(),
        collectAccountDeliveryIds(accountId),
      ]);
      await emitEventToGroupMembers({
        groupId,
        eventName: 'groupTyping',
        payload: {
          groupId: String(groupId),
          userId: String(accountId),
          username: user?.username ?? 'Member',
        },
        excludeUserIds: senderRooms,
      });
    } catch (err) {
      console.error('Error relaying groupTyping:', err);
    }
  });

  socket.on('groupStopTyping', async ({ groupId } = {}) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !groupId) return;
    try {
      const { userId: accountId } = await resolveAccountUserId(authedUserId);
      const { ids: senderRooms } = await collectAccountDeliveryIds(accountId);
      await emitEventToGroupMembers({
        groupId,
        eventName: 'groupStopTyping',
        payload: { groupId: String(groupId), userId: String(accountId) },
        excludeUserIds: senderRooms,
      });
    } catch (err) {
      console.error('Error relaying groupStopTyping:', err);
    }
  });

  socket.on('sendGroupWelcome', async ({ groupId, recipientUserId, welcome }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const recipientUserIdStr = String(recipientUserId ?? '');
    if (!welcome || typeof welcome !== 'object' || !recipientUserIdStr || !groupIdStr) {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, resolved, recipientMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
        GroupMember.findOne({ groupId: groupIdStr, userId: recipientUserIdStr }).lean(),
      ]);
      const senderMembership = resolved.membership;
      const sender = await User.findOne({ id: resolved.userId }).lean();

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership || senderMembership.status === 'removed') {
        return cb?.({
          success: false,
          error: 'forbidden',
          details: !senderMembership
            ? `No group membership for socket user ${authedUserId} (resolved ${resolved.userId} via ${resolved.resolvedVia}) in group ${groupIdStr}`
            : `Group membership for ${resolved.userId} is ${senderMembership.status}`,
        });
      }
      if (!recipientMembership || recipientMembership.status === 'removed') {
        return cb?.({ success: false, error: 'Recipient is not a member of the group' });
      }
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(welcome.groupId ?? '') !== groupIdStr) return cb?.({ success: false, error: 'Welcome groupId mismatch' });
      if (String(welcome.recipientUserId ?? '') !== recipientUserIdStr) return cb?.({ success: false, error: 'Welcome recipient mismatch' });

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: resolved.userId,
        senderUsername: sender.username,
        targetUserId: recipientUserIdStr,
        epoch: welcome.epoch,
        senderLeafIndex: senderMembership.leafIndex,
        contentType: 'welcome',
        artifact: welcome,
      });

      // Broadcast to every device room for the recipient account. Each device
      // filters by welcome.recipientClientId to decide whether to process.
      const { ids: welcomeDeliveryIds } = await collectAccountDeliveryIds(recipientUserIdStr);
      for (const deliveryId of welcomeDeliveryIds) {
        io.to(deliveryId).emit('groupWelcome', { groupId: groupIdStr, welcome });
      }
      return cb?.({ success: true, delivered: true });
    } catch (err) {
      console.error('Error sending group welcome:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('requestSiblingGroupMlsBootstrap', async ({ groupId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr) return cb?.({ success: false, error: 'Missing groupId' });

    try {
      const requesterDeviceId = socket.user?.deviceId ? String(socket.user.deviceId) : null;
      const { ids } = await collectAccountDeliveryIds(authedUserId);
      const requesterRooms = new Set([String(authedUserId)]);
      if (requesterDeviceId) requesterRooms.add(requesterDeviceId);

      let notified = 0;
      for (const id of ids) {
        if (!id || requesterRooms.has(id)) continue;
        io.to(id).emit('siblingGroupMlsBootstrapRequest', {
          groupId: groupIdStr,
          requesterDeviceId,
        });
        notified += 1;
      }

      return cb?.({ success: true, notified });
    } catch (err) {
      console.error('Error requesting sibling MLS bootstrap:', err);
      return cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('fetchPendingWelcomes', async (_, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    try {
      const { ids: welcomeTargetIds } = await collectAccountDeliveryIds(authedUserId);
      const stored = await Message.find({
        conversationType: 'group',
        contentType: 'welcome',
        targetUserId: { $in: welcomeTargetIds },
      }).lean();

      const thisDeviceClientId = socket.user?.deviceId ? String(socket.user.deviceId) : null;
      const welcomes = stored
        .map((msg) => {
          try {
            const welcome = JSON.parse(msg.payload);
            const targetClientId = welcome?.recipientClientId ?? null;
            if (
              targetClientId !== null &&
              thisDeviceClientId &&
              targetClientId !== thisDeviceClientId
            ) {
              return null;
            }
            return { groupId: msg.groupId, welcome };
          } catch {
            return null;
          }
        })
        .filter(Boolean);

      cb?.({ success: true, welcomes });
    } catch (err) {
      console.error('Error fetching pending welcomes:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('sendGroupCommit', async ({ groupId, commit }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr || !commit || typeof commit !== 'object') return cb?.({ success: false, error: 'Missing required fields' });

    try {
      const [group, resolved] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
      ]);
      const senderMembership = resolved.membership;
      const sender = await User.findOne({ id: resolved.userId }).lean();

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership || senderMembership.status === 'removed') {
        return cb?.({
          success: false,
          error: 'forbidden',
          details: !senderMembership
            ? `No group membership for socket user ${authedUserId} (resolved ${resolved.userId} via ${resolved.resolvedVia}) in group ${groupIdStr}`
            : `Group membership for ${resolved.userId} is ${senderMembership.status}`,
        });
      }
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(commit.groupId ?? '') !== groupIdStr) return cb?.({ success: false, error: 'Commit groupId mismatch' });
      // Item #17: reject commits that don't advance the epoch by exactly 1.
      if (Number.isInteger(commit.epoch) && commit.epoch !== group.epoch + 1) {
        return cb?.({ success: false, error: 'Invalid commit epoch' });
      }

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: resolved.userId,
        senderUsername: sender.username,
        epoch: commit.epoch,
        senderLeafIndex: commit.senderLeafIndex,
        contentType: 'commit',
        artifact: commit,
      });

      if (Number.isInteger(commit.epoch)) {
        await Group.updateOne(
          { groupId: groupIdStr },
          { $max: { epoch: commit.epoch }, $set: { updatedAt: new Date() } }
        );
      }

      const delivered = await emitEventToGroupMembers({
        groupId: groupIdStr,
        eventName: 'groupCommit',
        payload: { groupId: groupIdStr, commit },
      });

      return cb?.({ success: true, delivered });
    } catch (err) {
      console.error('Error sending group commit:', err);
      return cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('publishKeyPackage', async ({ keyPackage, initKeyB64, clientId }, cb) => {
    const authedUserId = String(socket.user?.id ?? '');
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    // Item #20: clientId scopes the package to a specific device/session.
    // null means "default client" for backward compatibility.
    const resolvedClientId = typeof clientId === 'string' && clientId.length > 0 ? clientId : null;

    try {
      const account = await resolveAccountUserId(authedUserId);
      const userId = account.userId;
      if (keyPackage && typeof keyPackage === 'object') {
        const blob = JSON.stringify(keyPackage);
        if (blob.length > 16384) return cb?.({ success: false, error: 'KeyPackage too large' });
        const initKey = typeof keyPackage.initKeyB64 === 'string' ? keyPackage.initKeyB64 : null;
        // Item #9 + #20: upsert by (userId, clientId) so each device has its own package;
        // reset consumed=false so the refreshed package is eligible for new Add commits.
        await KeyPackage.findOneAndUpdate(
          { userId, clientId: resolvedClientId },
          { $set: { userId, clientId: resolvedClientId, keyPackage, initKeyB64: initKey, consumed: false, updatedAt: new Date() } },
          { upsert: true, new: true, runValidators: false, setDefaultsOnInsert: true }
        );
      } else if (typeof initKeyB64 === 'string' && initKeyB64.trim().length > 0) {
        await KeyPackage.findOneAndUpdate(
          { userId, clientId: resolvedClientId },
          { $set: { userId, clientId: resolvedClientId, initKeyB64: initKeyB64.trim(), consumed: false, updatedAt: new Date() } },
          { upsert: true, new: true, runValidators: false, setDefaultsOnInsert: true }
        );
      } else {
        return cb?.({ success: false, error: 'Missing keyPackage or initKeyB64' });
      }
      cb?.({ success: true });
    } catch (err) {
      console.error('publishKeyPackage error:', err?.message);
      cb?.({ success: false, error: err?.message || 'Internal server error' });
    }
  });

  socket.on('fetchKeyPackage', async ({ userId: targetId, consume }, cb) => {
    const callerId = socket.user?.id;
    if (!callerId) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const userIdStr = String(targetId ?? '');
      // Item #9: prefer a non-consumed package; fall back to any package for backward compat.
      // Sort by createdAt ascending so oldest packages are consumed first (FIFO pool).
      let candidates = await KeyPackage.find({ userId: userIdStr, consumed: false })
        .sort({ createdAt: 1 })
        .lean();
      let reachable = await filterReachableKeyPackages(userIdStr, candidates);
      let kp = reachable[0] ?? null;
      if (!kp) {
        candidates = await KeyPackage.find({ userId: userIdStr }).sort({ createdAt: 1 }).lean();
        reachable = await filterReachableKeyPackages(userIdStr, candidates);
        kp = reachable[0] ?? null;
      }
      if (!kp) return cb?.({ success: false, error: 'KeyPackage not found' });

      // Item #9: atomically mark as consumed when the caller signals it will be used
      // for an Add commit (consume=true). This prevents KeyPackage reuse.
      if (consume === true && !kp.consumed) {
        await KeyPackage.updateOne({ _id: kp._id }, { $set: { consumed: true } });
      }

      if (kp.keyPackage) {
        cb?.({ success: true, keyPackage: kp.keyPackage, initKeyB64: kp.initKeyB64 });
      } else {
        cb?.({ success: true, initKeyB64: kp.initKeyB64 });
      }
    } catch (err) {
      console.error('fetchKeyPackage error:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  // Return ALL key packages for a user (one per device/clientId).
  // Used by group creators to add each device as a separate MLS leaf.
  socket.on('fetchAllKeyPackages', async ({ userId: targetId }, cb) => {
    const callerId = socket.user?.id;
    if (!callerId) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const userIdStr = String(targetId ?? '');
      const packages = await KeyPackage.find({ userId: userIdStr, consumed: false })
        .sort({ updatedAt: -1, createdAt: -1 })
        .lean();
      let result = packages.length > 0
        ? packages
        : await KeyPackage.find({ userId: userIdStr }).sort({ updatedAt: -1, createdAt: -1 }).lean();
      result = await filterReachableKeyPackages(userIdStr, result);
      cb?.({
        success: true,
        packages: result.map((kp) => ({
          id: String(kp._id ?? ''),
          clientId: kp.clientId ?? null,
          initKeyB64: kp.initKeyB64 ?? null,
          keyPackage: kp.keyPackage ?? null,
          createdAt: kp.createdAt ?? null,
          updatedAt: kp.updatedAt ?? null,
        })),
      });
    } catch (err) {
      console.error('fetchAllKeyPackages error:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('consumeKeyPackage', async ({ packageId }, cb) => {
    const callerId = socket.user?.id;
    if (!callerId) return cb?.({ success: false, error: 'unauthorized' });
    const packageIdStr = String(packageId ?? '');
    if (!packageIdStr) return cb?.({ success: false, error: 'Missing required fields' });

    try {
      await KeyPackage.updateOne({ _id: packageIdStr }, { $set: { consumed: true } });
      cb?.({ success: true });
    } catch (err) {
      console.error('consumeKeyPackage error:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  // Clients send a proposal before committing in MLS groups.
  // Server stores it opaquely and broadcasts to all group members.
  socket.on('sendGroupProposal', async ({ groupId, proposal }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    if (!groupIdStr || !proposal || typeof proposal !== 'object') {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, resolved] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
      ]);
      const membership = resolved.membership;
      const sender = await User.findOne({ id: resolved.userId }).lean();

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!membership || membership.status === 'removed') {
        return cb?.({
          success: false,
          error: 'forbidden',
          details: !membership
            ? `No group membership for socket user ${authedUserId} (resolved ${resolved.userId} via ${resolved.resolvedVia}) in group ${groupIdStr}`
            : `Group membership for ${resolved.userId} is ${membership.status}`,
        });
      }
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (!group.mlsEnabled) return cb?.({ success: false, error: 'Not an MLS group' });
      if (String(proposal.groupId ?? '') !== groupIdStr) {
        return cb?.({ success: false, error: 'Proposal groupId mismatch' });
      }

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: resolved.userId,
        senderUsername: sender.username,
        epoch: proposal.epoch,
        senderLeafIndex: proposal.senderLeafIndex,
        contentType: 'proposal',
        artifact: proposal,
      });

      const delivered = await emitEventToGroupMembers({
        groupId: groupIdStr,
        eventName: 'groupProposal',
        payload: { groupId: groupIdStr, proposal },
      });

      cb?.({ success: true, delivered });
    } catch (err) {
      console.error('Error sending group proposal:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  // Two-phase membership commit: the DB mutation happens only after the client has
  // successfully applied the MLS commit locally and calls this event.
  // This prevents the DB state from diverging from the cryptographic state.
  socket.on('confirmMlsCommit', async ({ groupId, epoch, type, targetUserId }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const targetUserIdStr = String(targetUserId ?? '');

    if (!groupIdStr || !type || !Number.isInteger(epoch)) {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, resolved] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        resolveGroupUserId(groupIdStr, authedUserId),
      ]);
      const callerMembership = resolved.membership;
      const sender = await User.findOne({ id: resolved.userId }).lean();

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!group.mlsEnabled) return cb?.({ success: false, error: 'Not an MLS group' });
      if (!callerMembership || callerMembership.status === 'removed' || callerMembership.role !== 'admin') {
        return cb?.({
          success: false,
          error: 'forbidden',
          details: !callerMembership
            ? `No group membership for socket user ${authedUserId} (resolved ${resolved.userId} via ${resolved.resolvedVia}) in group ${groupIdStr}`
            : `Group membership for ${resolved.userId} is ${callerMembership.status}/${callerMembership.role}`,
        });
      }
      if (group.epoch + 1 !== epoch) {
        return cb?.({ success: false, error: 'Epoch mismatch — another commit may have won the race' });
      }

      if (type === 'add' && targetUserIdStr) {
        const { ids: addTargetIds } = await collectAccountDeliveryIds(targetUserIdStr);
        await GroupMember.updateMany(
          { groupId: groupIdStr, userId: { $in: addTargetIds } },
          { $set: { status: 'active' } }
        );
      } else if (type === 'remove' && targetUserIdStr) {
        const { account: removedAccount, ids: removeTargetIds } =
          await collectAccountDeliveryIds(targetUserIdStr);
        const canonicalMemberId = String(removedAccount.userId || targetUserIdStr);
        await GroupMember.updateMany(
          { groupId: groupIdStr, userId: { $in: removeTargetIds } },
          { $set: { status: 'removed' } }
        );
        const room = `group:${groupIdStr}`;
        const nowIso = new Date().toISOString();
        for (const deliveryId of removeTargetIds) {
          io.in(deliveryId).socketsLeave(room);
          io.to(deliveryId).emit('groupRemoved', {
            groupId: groupIdStr,
            memberId: canonicalMemberId,
            removedByUserId: resolved.userId,
            removedByUsername: sender?.username ?? null,
            groupName: group.name,
            at: nowIso,
          });
        }
        io.to(room).emit('groupMemberRemoved', {
          groupId: groupIdStr,
          memberId: canonicalMemberId,
          removedByUserId: resolved.userId,
          removedByUsername: sender?.username ?? null,
          groupName: group.name,
          at: nowIso,
        });
      }

      await Group.updateOne({ groupId: groupIdStr }, { $set: { epoch } });
      cb?.({ success: true });
    } catch (err) {
      console.error('Error confirming MLS commit:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });
}

module.exports = { registerGroupsSocketHandlers };
