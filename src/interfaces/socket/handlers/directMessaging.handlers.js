function registerDirectMessagingSocketHandlers(deps) {
  const {
    socket,
    io,
    userSocketMap,
    Message,
    User,
    MessageSequence,
    makeConversationKey,
    ensureConversationSequence,
  } = deps;

  socket.on('messageSeen', async (data) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return;

    const { targetUserId } = data;
    console.log('Message from ', authedUserId, ' seen by ', targetUserId);

    try {
      const result = await Message.updateMany(
        { userId: targetUserId, targetUserId: authedUserId, seenStatus: false },
        { $set: { seenStatus: true } }
      );

      console.log('Updated messages seenStatus:', result);

      io.to(targetUserId).emit('messageSeenUpdate', { userId: authedUserId, targetUserId });
    } catch (err) {
      console.error('Error updating seenStatus:', err);
    }
  });

  socket.on('checkIfMessagesExist', async (data, callback) => {
    const authedUserId = socket.user?.id;
    const { targetUserId } = data ?? {};
    if (!authedUserId || !targetUserId) return callback?.({ success: false });

    try {
      const message_1 = await Message.findOne({ userId: authedUserId, targetUserId });
      const message_2 = await Message.findOne({ userId: targetUserId, targetUserId: authedUserId });
      callback({ success: Boolean(message_1 || message_2) });
    } catch (err) {
      console.error('Error checking messages:', err);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getLatestMessageNumber', async (data, callback) => {
    const authedUserId = socket.user?.id;
    const { targetUserId, senderDeviceId, peerDeviceId, senderDeviceUserId, peerDeviceUserId } = data ?? {};
    if (!authedUserId || !targetUserId) {
      return callback?.({ success: false, messageNumber: 0 });
    }

    try {
      const conversationKey = makeConversationKey(authedUserId, targetUserId, {
        devA: senderDeviceUserId ? String(senderDeviceUserId) : (senderDeviceId ? String(senderDeviceId) : null),
        devB: peerDeviceUserId ? String(peerDeviceUserId) : (peerDeviceId ? String(peerDeviceId) : null),
      });
      const seq = await ensureConversationSequence(conversationKey, authedUserId, targetUserId);
      const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;
      callback({ success: true, messageNumber: last });
    } catch (err) {
      console.error('Error:', err);
      callback({ success: false, messageNumber: 0 });
    }
  });

  socket.on('newMessage', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const ack = (payload) => {
      if (typeof callback === 'function') callback(payload);
    };

    const {
      is_initial, payload, nonce, targetUserId,
      messageNumber, sendingNumber, previousSendingNumber,
      publicEphemeralKey, spkId, opkId,
      senderDeviceId: senderDeviceIdRaw, peerDeviceId: peerDeviceIdRaw,
      senderDeviceUserId: senderDeviceUserIdRaw, peerDeviceUserId: peerDeviceUserIdRaw,
      conversationUserId: conversationUserIdRaw,
    } = data;

    const targetUserIdStr = String(targetUserId ?? '');
    const incomingNumber = Number(messageNumber);
    const senderDeviceId = senderDeviceIdRaw ? String(senderDeviceIdRaw) : null;
    const peerDeviceId = peerDeviceIdRaw ? String(peerDeviceIdRaw) : null;
    const senderDeviceUserId = senderDeviceUserIdRaw ? String(senderDeviceUserIdRaw) : null;
    const peerDeviceUserId = peerDeviceUserIdRaw ? String(peerDeviceUserIdRaw) : null;
    const conversationUserId = conversationUserIdRaw ? String(conversationUserIdRaw) : null;

    if ((!payload) || !authedUserId || !targetUserIdStr) {
      ack({ success: false, error: 'Missing required fields' });
      return;
    }

    if (!Number.isSafeInteger(incomingNumber) || incomingNumber < 0) {
      ack({ success: false, error: 'Invalid messageNumber' });
      return;
    }

    // Per-device fanout messages use a (sender_device, recipient_device)
    // conversation key so each device-pair maintains its own message
    // sequence and N fanout copies don't race a single sender→recipient
    // sequence.
    const conversationKey = makeConversationKey(authedUserId, targetUserIdStr, {
      devA: senderDeviceUserId || senderDeviceId,
      devB: peerDeviceUserId || peerDeviceId,
    });

    try {
      const sender = await User.findOne({ id: authedUserId });
      if (!sender) {
        ack({ success: false, error: 'Sender not found' });
        return;
      }

      await ensureConversationSequence(conversationKey, authedUserId, targetUserIdStr);

      const updated = await MessageSequence.findOneAndUpdate(
        { conversationKey, lastMessageNumber: incomingNumber - 1 },
        { $set: { lastMessageNumber: incomingNumber, lastSenderId: authedUserId, updatedAt: new Date() } },
        { new: true }
      );

      if (!updated) {
        const seq = await MessageSequence.findOne({ conversationKey }).lean();
        const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;

        if (incomingNumber <= last) {
          ack({ success: false, error: 'replay_detected', lastAccepted: last });
          return;
        }
        ack({ success: false, error: 'out_of_sync', lastAccepted: last });
        return;
      }

      const message = new Message({
        is_initial,
        payload,
        nonce,
        userId: authedUserId,
        targetUserId: targetUserIdStr,
        conversationKey,
        username: sender.username,
        seenStatus: false,
        messageNumber: incomingNumber,
        sendingNumber,
        previousSendingNumber,
        publicEphemeralKey,
        spkId: spkId ?? null,
        opkId: opkId ?? null,
        senderDeviceId,
        peerDeviceId,
        senderDeviceUserId,
        peerDeviceUserId,
        conversationUserId,
        conversationType: 'direct',
      });

      await message.save();
      const messageWithProfile = {
        ...message.toObject(),
        profileImage: sender.profilePicture || null,
        timestamp: message.createdAt,
      };

      // Deliver to every device of BOTH the sender and the recipient. The
      // sender's siblings need their fanout copy too (each device runs its
      // own DR — there is no per-account plaintext-forward channel any more).
      // Receivers self-filter by peerDeviceId; the sender's own socket will
      // see broadcasts of its own fanout but every copy carries a
      // peerDeviceId that doesn't match the sender's deviceId, so it
      // silently drops them.
      io.to(authedUserId).emit('newMessage', messageWithProfile);
      if (targetUserIdStr !== authedUserId) {
        io.to(targetUserIdStr).emit('newMessage', messageWithProfile);
      }

      ack({ success: true });
    } catch (err) {
      console.error('Error saving message:', err);
      try {
        await MessageSequence.updateOne(
          { conversationKey, lastMessageNumber: incomingNumber },
          { $set: { lastMessageNumber: incomingNumber - 1, updatedAt: new Date() } }
        );
      } catch { }
      ack({ success: false, error: 'Error saving message' });
    }
  });
}

module.exports = { registerDirectMessagingSocketHandlers };
