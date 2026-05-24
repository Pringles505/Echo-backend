const { BadRequestError } = require('../../../shared/errors');

function createMessagingService({
  Message,
  MessageSequence,
  makeConversationKey,
  ensureConversationSequence,
  notifier,
} = {}) {
  if (!Message) throw new Error('createMessagingService requires Message model');
  if (typeof makeConversationKey !== 'function') {
    throw new Error('createMessagingService requires makeConversationKey()');
  }
  if (typeof ensureConversationSequence !== 'function') {
    throw new Error('createMessagingService requires ensureConversationSequence()');
  }

  function normalizeIds({ userId, targetUserId }) {
    const a = typeof userId === 'string' ? userId.trim() : '';
    const b = typeof targetUserId === 'string' ? targetUserId.trim() : '';
    if (!a) throw new BadRequestError('Missing authenticated user', 'validation_error');
    if (!b) throw new BadRequestError('Missing required field: targetUserId', 'validation_error', 'targetUserId');
    return { authedUserId: a, targetUserIdStr: b };
  }

  return {
    async checkMessagesExist({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });
      const [outgoing, incoming] = await Promise.all([
        Message.findOne({ userId: authedUserId, targetUserId: targetUserIdStr }),
        Message.findOne({ userId: targetUserIdStr, targetUserId: authedUserId }),
      ]);
      return { exists: Boolean(outgoing || incoming) };
    },

    async getLatestMessageNumber({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });
      const conversationKey = makeConversationKey(authedUserId, targetUserIdStr);
      const seq = await ensureConversationSequence(conversationKey, authedUserId, targetUserIdStr);
      const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;
      return { messageNumber: last };
    },

    async markMessagesSeen({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });

      const result = await Message.updateMany(
        { userId: targetUserIdStr, targetUserId: authedUserId, seenStatus: false },
        { $set: { seenStatus: true } }
      );

      if (notifier && typeof notifier.emitToUser === 'function') {
        notifier.emitToUser(targetUserIdStr, 'messageSeenUpdate', {
          userId: authedUserId,
          targetUserId: targetUserIdStr,
        });
      }

      const updatedCount = Number.isFinite(result?.modifiedCount)
        ? result.modifiedCount
        : Number.isFinite(result?.nModified) ? result.nModified : 0;
      return { updatedCount };
    },
  };
}

module.exports = { createMessagingService };
