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
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
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
    userSocketMap,
    Message,
    User,
    Group,
    GroupMember,
    GroupSequence,
    KeyPackage,
    ensureGroupSequence,
  } = deps;

  const emitEventToGroupMembers = async ({ groupId, eventName, payload, excludeUserIds = [] }) => {
    const groupIdStr = String(groupId ?? '');
    const exclude = new Set(excludeUserIds.map((userId) => String(userId ?? '')).filter(Boolean));
    const members = await GroupMember.find({ groupId: groupIdStr }, { userId: 1 }).lean();

    let deliveredCount = 0;
    for (const member of members) {
      const memberId = String(member?.userId ?? '');
      if (!memberId || exclude.has(memberId)) continue;
      const memberSocketId = userSocketMap[memberId];
      if (!memberSocketId) continue;
      io.to(memberSocketId).emit(eventName, payload);
      deliveredCount += 1;
    }
    return deliveredCount;
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

    const [group, membership] = await Promise.all([
      Group.findOne({ groupId: groupIdStr }).lean(),
      GroupMember.findOne({ groupId: groupIdStr, userId: authedUserIdStr }).lean(),
    ]);

    if (!group) return { ok: false, error: 'Group not found' };
    if (!membership) return { ok: false, error: 'forbidden' };

    const members = await GroupMember.find({ groupId: groupIdStr }).lean();
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
      ? (typeof cipherSuite === 'string' && cipherSuite.trim().length > 0 ? cipherSuite.trim() : 'MLS-MVP/X25519_AES256GCM_SHA256')
      : null;

    const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
    const authedUserIdStr = String(authedUserId);
    const normalizedMemberIds = [...new Set(memberIds.map((m) => String(m ?? '')).filter(Boolean))].filter((id) => id !== authedUserIdStr);
    if (normalizedMemberIds.length === 0) return cb?.({ success: false, error: 'At least one member is required' });

    const emitToUser = (targetUserId, eventName, payload) => {
      const socketId = userSocketMap[String(targetUserId)];
      if (socketId) io.to(socketId).emit(eventName, payload);
    };

    const nowIso = new Date().toISOString();
    let groupId = null;

    try {
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
        emitToUser(memberId, 'groupAdded', { groupId, name, addedByUserId: authedUserIdStr, role: 'member', at: nowIso });
      }

      emitToUser(authedUserIdStr, 'groupAdded', { groupId, name, addedByUserId: authedUserIdStr, role: 'admin', at: nowIso });
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
      const authedUserIdStr = String(authedUserId);
      const memberships = await GroupMember.find({ userId: authedUserIdStr }).lean();
      const groupIds = memberships.map((m) => String(m.groupId)).filter(Boolean);
      const groups = await Group.find({ groupId: { $in: groupIds } }).lean();
      const groupById = new Map(groups.map((g) => [String(g.groupId), g]));
      const result = memberships.map((m) => {
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
      const membership = await GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean();
      if (!membership) return cb?.({ success: false, error: 'forbidden' });

      const safeLimit = Math.max(1, Math.min(Number(limit) || 50, 200));
      const query = {
        conversationType: 'group',
        groupId: groupIdStr,
        $or: [{ targetUserId: null }, { targetUserId: String(authedUserId) }],
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
      const [group, callerMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
      ]);
      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership || callerMembership.role !== 'admin') return cb?.({ success: false, error: 'forbidden' });

      const existing = await GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean();
      if (existing) return cb?.({ success: false, error: 'already_member' });

      const existingMembers = await GroupMember.find({ groupId: groupIdStr }, { leafIndex: 1 }).lean();
      const maxLeafIndex = existingMembers.reduce((max, member) => (Number.isInteger(member.leafIndex) && member.leafIndex > max ? member.leafIndex : max), -1);
      const nextLeafIndex = maxLeafIndex + 1;

      await GroupMember.create({
        groupId: groupIdStr,
        userId: memberIdStr,
        role: 'member',
        joinedAt: new Date(),
        leafIndex: nextLeafIndex,
        status: 'active',
      });

      const nowIso = new Date().toISOString();
      const room = `group:${groupIdStr}`;
      const memberSocketId = userSocketMap[memberIdStr];
      if (memberSocketId) {
        io.to(memberSocketId).emit('groupAdded', {
          groupId: groupIdStr,
          name: group.name,
          addedByUserId: String(authedUserId),
          role: 'member',
          at: nowIso,
        });
      }

      io.to(room).emit('groupMemberAdded', {
        groupId: groupIdStr,
        memberId: memberIdStr,
        addedByUserId: String(authedUserId),
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
      const [group, callerMembership, targetMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!callerMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!targetMembership) return cb?.({ success: false, error: 'not_a_member' });

      const isSelf = String(authedUserId) === memberIdStr;
      const canRemove = isSelf || (callerMembership.role === 'admin' && (targetMembership.role !== 'admin' || isSelf));
      if (!canRemove) return cb?.({ success: false, error: 'forbidden' });

      await GroupMember.deleteOne({ groupId: groupIdStr, userId: memberIdStr });

      const room = `group:${groupIdStr}`;
      const nowIso = new Date().toISOString();
      const memberSocketId = userSocketMap[memberIdStr];
      if (memberSocketId) {
        const memberSocket = io.sockets.sockets.get(memberSocketId);
        if (memberSocket) memberSocket.leave(room);
        io.to(memberSocketId).emit('groupRemoved', { groupId: groupIdStr, at: nowIso });
      }

      io.to(room).emit('groupMemberRemoved', {
        groupId: groupIdStr,
        memberId: memberIdStr,
        removedByUserId: String(authedUserId),
        at: nowIso,
      });

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
      epoch,
      senderLeafIndex,
    } = data ?? {};

    const groupIdStr = String(groupId ?? '');

    try {
      const [sender, group, membership] = await Promise.all([
        User.findOne({ id: authedUserId }),
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: authedUserId }).lean(),
      ]);
      if (!sender) return ack({ success: false, error: 'Sender not found' });
      if (!group) return ack({ success: false, error: 'Group not found' });
      if (!membership) return ack({ success: false, error: 'Forbidden' });
      if (!groupIdStr) return ack({ success: false, error: 'Missing required fields' });

      const isMlsGroup = group.mlsEnabled === true;
      if (isMlsGroup) {
        const validContentTypes = new Set(['application', 'commit', 'welcome']);
        if (
          typeof contentType !== 'string' ||
          !validContentTypes.has(contentType) ||
          typeof headerB64 !== 'string' ||
          headerB64.length === 0 ||
          typeof ciphertextB64 !== 'string' ||
          ciphertextB64.length === 0 ||
          typeof epoch !== 'number' ||
          !Number.isInteger(senderLeafIndex)
        ) {
          return ack({ success: false, error: 'Missing required fields' });
        }
        if (membership.leafIndex !== senderLeafIndex) return ack({ success: false, error: 'Forbidden' });
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
        userId: authedUserId,
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
        headerB64: isMlsGroup ? headerB64 : null,
        ciphertextB64: isMlsGroup ? ciphertextB64 : null,
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
      };

      io.to(room).emit('newGroupMessage', messageWithProfile);

      const members = await GroupMember.find({ groupId: groupIdStr }, { userId: 1 }).lean();
      for (const m of members) {
        const memberId = String(m?.userId ?? '');
        const memberSocketId = userSocketMap[memberId];
        if (!memberSocketId) continue;
        const memberSocket = io.sockets.sockets.get(memberSocketId);
        if (!memberSocket || !memberSocket.rooms?.has(room)) {
          io.to(memberSocketId).emit('newGroupMessage', messageWithProfile);
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

  socket.on('sendGroupWelcome', async ({ groupId, recipientUserId, welcome }, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    const groupIdStr = String(groupId ?? '');
    const recipientUserIdStr = String(recipientUserId ?? '');
    const senderUserIdStr = String(authedUserId);

    if (!welcome || typeof welcome !== 'object' || !recipientUserIdStr || !groupIdStr) {
      return cb?.({ success: false, error: 'Missing required fields' });
    }

    try {
      const [group, senderMembership, recipientMembership, sender] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: senderUserIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: recipientUserIdStr }).lean(),
        User.findOne({ id: senderUserIdStr }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!recipientMembership) return cb?.({ success: false, error: 'Recipient is not a member of the group' });
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(welcome.groupId ?? '') !== groupIdStr) return cb?.({ success: false, error: 'Welcome groupId mismatch' });
      if (String(welcome.recipientUserId ?? '') !== recipientUserIdStr) return cb?.({ success: false, error: 'Welcome recipient mismatch' });

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: senderUserIdStr,
        senderUsername: sender.username,
        targetUserId: recipientUserIdStr,
        epoch: welcome.epoch,
        senderLeafIndex: senderMembership.leafIndex,
        contentType: 'welcome',
        artifact: welcome,
      });

      const recipientSocketId = userSocketMap[recipientUserIdStr];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('groupWelcome', { groupId: groupIdStr, welcome });
      }
      return cb?.({ success: true, delivered: Boolean(recipientSocketId) });
    } catch (err) {
      console.error('Error sending group welcome:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('fetchPendingWelcomes', async (_, cb) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return cb?.({ success: false, error: 'unauthorized' });

    try {
      const stored = await Message.find({
        conversationType: 'group',
        contentType: 'welcome',
        targetUserId: String(authedUserId),
      }).lean();

      const welcomes = stored.map((msg) => {
        try {
          const welcome = JSON.parse(msg.payload);
          return { groupId: msg.groupId, welcome };
        } catch {
          return null;
        }
      }).filter(Boolean);

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
      const [group, senderMembership, sender] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: String(authedUserId) }).lean(),
        User.findOne({ id: String(authedUserId) }).lean(),
      ]);

      if (!group) return cb?.({ success: false, error: 'Group not found' });
      if (!senderMembership) return cb?.({ success: false, error: 'forbidden' });
      if (!sender) return cb?.({ success: false, error: 'Sender not found' });
      if (String(commit.groupId ?? '') !== groupIdStr) return cb?.({ success: false, error: 'Commit groupId mismatch' });
      if (
        Number.isInteger(commit.senderLeafIndex) &&
        Number.isInteger(senderMembership.leafIndex) &&
        commit.senderLeafIndex !== senderMembership.leafIndex
      ) {
        return cb?.({ success: false, error: 'Forbidden' });
      }

      await persistGroupArtifactMessage({
        groupId: groupIdStr,
        senderUserId: String(authedUserId),
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

  socket.on('publishKeyPackage', async ({ initKeyB64 }, cb) => {
    const userId = String(socket.user?.id ?? '');
    const normalizedInitKeyB64 = typeof initKeyB64 === 'string' ? initKeyB64.trim() : '';
    if (!userId) return cb?.({ success: false, error: 'unauthorized' });
    if (!normalizedInitKeyB64) return cb?.({ success: false, error: 'Missing initKeyB64' });

    try {
      await KeyPackage.findOneAndUpdate(
        { userId },
        { $set: { userId, initKeyB64: normalizedInitKeyB64, updatedAt: new Date() } },
        {
          upsert: true,
          new: true,
          runValidators: true,
          setDefaultsOnInsert: true,
        }
      );
      cb?.({ success: true });
    } catch (err) {
      console.error('publishKeyPackage error:', {
        userId,
        initKeyLength: normalizedInitKeyB64.length,
        message: err?.message,
        code: err?.code,
        stack: err?.stack,
      });
      cb?.({ success: false, error: err?.message || 'Internal server error' });
    }
  });

  socket.on('fetchKeyPackage', async ({ userId: targetId }, cb) => {
    const callerId = socket.user?.id;
    if (!callerId) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const kp = await KeyPackage.findOne({ userId: String(targetId ?? '') }).lean();
      if (!kp) return cb?.({ success: false, error: 'KeyPackage not found' });
      cb?.({ success: true, initKeyB64: kp.initKeyB64 });
    } catch (err) {
      console.error('fetchKeyPackage error:', err);
      cb?.({ success: false, error: 'Internal server error' });
    }
  });
}

module.exports = { registerGroupsSocketHandlers };
