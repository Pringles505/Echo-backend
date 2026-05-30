/**
 * Socket event handlers for direct (1-to-1) messaging.
 * Implements replay attack prevention via message sequence numbers.
 * @module interfaces/socket/handlers/directMessaging
 */

/**
 * @typedef {object} MessageSeenPayload
 * @property {string} targetUserId - User ID whose messages were seen
 * @property {string} [conversationKey] - When present, only messages in this
 *   per-device conversation are marked seen (per-device fanout correctness).
 */

/**
 * @typedef {object} MessageDeliveredPayload
 * @property {string} targetUserId - The original sender whose messages reached
 *   this device (i.e. the user to notify with the delivered receipt).
 * @property {string} [conversationKey] - Optional per-device conversation scope.
 */

/**
 * @typedef {object} CheckMessagesPayload
 * @property {string} targetUserId - User ID to check conversation with
 */

/**
 * @typedef {object} CheckMessagesAckResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} LatestMessageNumberPayload
 * @property {string} targetUserId - User ID in conversation
 */

/**
 * @typedef {object} LatestMessageNumberAckResponse
 * @property {boolean} success
 * @property {number} messageNumber - Last accepted message number
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} NewMessagePayload
 * @property {boolean} is_initial - Whether this is an initial message
 * @property {string} payload - Encrypted message content (base64)
 * @property {string} nonce - Encryption nonce
 * @property {string} targetUserId - Recipient user ID
 * @property {number} messageNumber - Message counter for replay prevention
 * @property {number} sendingNumber - Signal Protocol sending chain number
 * @property {number} previousSendingNumber - Previous sending chain number
 * @property {string} publicEphemeralKey - Ephemeral key for decryption
 * @property {number} [spkId] - Signed Pre-Key ID
 * @property {number} [opkId] - One-Time Pre-Key ID
 */

/**
 * @typedef {object} NewMessageAckResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if failed ('replay_detected', 'out_of_sync', etc.)
 * @property {number} [lastAccepted] - Last accepted message number if error
 */

/**
 * Registers Socket.IO handlers for direct messaging events.
 * Preserves backward-compatible event contracts for message delivery,
 * seen status tracking, and replay attack prevention.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
 * @param {import('mongoose').Model} deps.Message - Message model
 * @param {import('mongoose').Model} deps.User - User model
 * @param {import('mongoose').Model} deps.MessageSequence - Message sequence model
 * @param {function} deps.makeConversationKey - Generate conversation ID from user IDs
 * @param {function} deps.ensureConversationSequence - Ensure sequence document exists
 */
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

  /**
   * 'messageSeen' event - Mark messages from a user as seen.
   * Emits 'messageSeenUpdate' to the sender.
   * @event messageSeen
   * @type {MessageSeenPayload}
   */
  socket.on('messageSeen', async (data) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return;

    const { targetUserId, conversationKey } = data ?? {};
    if (!targetUserId) return;
    console.log('Message from ', authedUserId, ' seen by ', targetUserId);

    try {
      // Mark every still-unread message sent FROM the peer TO us as seen.
      // When a conversationKey is supplied, scope to that per-device fanout
      // conversation so sibling-device copies in other conversations aren't
      // touched; otherwise fall back to the account-level match.
      const filter = {
        userId: targetUserId,
        targetUserId: authedUserId,
        seenStatus: false,
      };
      if (conversationKey) filter.conversationKey = String(conversationKey);

      const seenAt = new Date();
      const result = await Message.updateMany(filter, {
        $set: { seenStatus: true, seenAt },
      });

      console.log('Updated messages seenStatus:', result);

      // The original sender flips their outgoing bubbles to "read". We also
      // notify the reader's own sibling devices so they can reconcile local
      // seen state / unread badges (payload.userId === their own id).
      const payload = { userId: authedUserId, targetUserId, seenAt: seenAt.toISOString() };
      io.to(targetUserId).emit('messageSeenUpdate', payload);
      if (authedUserId !== targetUserId) {
        io.to(authedUserId).emit('messageSeenUpdate', payload);
      }
    } catch (err) {
      console.error('Error updating seenStatus:', err);
    }
  });

  /**
   * 'messageDelivered' event - Mark messages from a peer as delivered to this
   * device (received + persisted), distinct from being read. Emits
   * 'messageDeliveredUpdate' to the original sender so their bubbles can show a
   * "delivered" state before the recipient actually opens the conversation.
   * @event messageDelivered
   * @type {MessageDeliveredPayload}
   */
  socket.on('messageDelivered', async (data) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return;

    const { targetUserId, conversationKey } = data ?? {};
    if (!targetUserId || targetUserId === authedUserId) return;

    try {
      // Stamp deliveredAt on still-undelivered inbound messages from the peer.
      // Never clobber a delivered/seen message; `deliveredAt: null` keeps this
      // idempotent so repeated delivered pings don't churn timestamps.
      const filter = {
        userId: targetUserId,
        targetUserId: authedUserId,
        deliveredAt: null,
      };
      if (conversationKey) filter.conversationKey = String(conversationKey);

      const deliveredAt = new Date();
      await Message.updateMany(filter, { $set: { deliveredAt } });

      io.to(targetUserId).emit('messageDeliveredUpdate', {
        userId: authedUserId,
        targetUserId,
        deliveredAt: deliveredAt.toISOString(),
      });
    } catch (err) {
      console.error('Error updating deliveredStatus:', err);
    }
  });

  /**
   * 'checkIfMessagesExist' event - Check if any messages exist in a conversation.
   * @event checkIfMessagesExist
   * @type {CheckMessagesPayload}
   * @param {CheckMessagesAckResponse} callback - Ack callback
   */
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

  /**
   * 'getLatestMessageNumber' event - Get the last accepted message number in a conversation.
   * Used by clients to sync message ordering.
   * @event getLatestMessageNumber
   * @type {LatestMessageNumberPayload}
   * @param {LatestMessageNumberAckResponse} callback - Ack callback
   */
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

  /**
   * 'newMessage' event - Receive and persist a new direct message.
   * Implements replay attack prevention via message sequencing.
   * Ack response indicates acceptance or failure with reason.
   * @event newMessage
   * @type {NewMessagePayload}
   * @param {NewMessageAckResponse} callback - Ack callback with status
   */
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
