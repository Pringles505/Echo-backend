/**
 * @module modules/messaging/application/messagingService
 *
 * Application service for direct messaging use cases consumed by the HTTP
 * layer. Mirrors the contracts implemented by the socket handlers in
 * `src/interfaces/socket/handlers/directMessaging.handlers.js`, but is
 * transport-agnostic and broadcasts via a `notifier` adapter rather than
 * touching `io`/`userSocketMap` directly.
 */

const { BadRequestError } = require('../../../shared/errors');

/**
 * @typedef {object} TargetUserInput
 * @property {string} userId - Authenticated user identifier
 * @property {string} targetUserId - Counterparty identifier
 */

/**
 * @typedef {object} CheckMessagesResult
 * @property {boolean} exists - Whether at least one message exists in the conversation
 */

/**
 * @typedef {object} LatestMessageNumberResult
 * @property {number} messageNumber - Last accepted sequence number, -1 if none
 */

/**
 * @typedef {object} MarkSeenResult
 * @property {number} updatedCount - Number of messages flipped to seen
 */

/**
 * @param {object} deps
 * @param {import('mongoose').Model} deps.Message
 * @param {import('mongoose').Model} [deps.MessageSequence]
 * @param {(a:string,b:string)=>string} deps.makeConversationKey
 * @param {(key:string,a:string,b:string)=>Promise<{lastMessageNumber:number}>} deps.ensureConversationSequence
 * @param {{ emitToUser: Function }} deps.notifier
 * @returns {{
 *   checkMessagesExist: (input: TargetUserInput) => Promise<CheckMessagesResult>,
 *   getLatestMessageNumber: (input: TargetUserInput) => Promise<LatestMessageNumberResult>,
 *   markMessagesSeen: (input: TargetUserInput) => Promise<MarkSeenResult>,
 * }}
 */
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
    /**
     * Check whether any message exists between `userId` and `targetUserId`,
     * in either direction.
     */
    async checkMessagesExist({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });
      const [outgoing, incoming] = await Promise.all([
        Message.findOne({ userId: authedUserId, targetUserId: targetUserIdStr }),
        Message.findOne({ userId: targetUserIdStr, targetUserId: authedUserId }),
      ]);
      return { exists: Boolean(outgoing || incoming) };
    },

    /**
     * Return the last accepted message number for a conversation, ensuring
     * that the sequence document exists.
     */
    async getLatestMessageNumber({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });
      const conversationKey = makeConversationKey(authedUserId, targetUserIdStr);
      const seq = await ensureConversationSequence(conversationKey, authedUserId, targetUserIdStr);
      const last = Number.isFinite(seq?.lastMessageNumber) ? seq.lastMessageNumber : -1;
      return { messageNumber: last };
    },

    /**
     * Mark every unread message sent FROM `targetUserId` TO `userId` as seen
     * and notify the sender via the configured notifier.
     */
    async markMessagesSeen({ userId, targetUserId }) {
      const { authedUserId, targetUserIdStr } = normalizeIds({ userId, targetUserId });

      const seenAt = new Date();
      const result = await Message.updateMany(
        { userId: targetUserIdStr, targetUserId: authedUserId, seenStatus: false },
        { $set: { seenStatus: true, seenAt } }
      );

      if (notifier && typeof notifier.emitToUser === 'function') {
        const payload = {
          userId: authedUserId,
          targetUserId: targetUserIdStr,
          seenAt: seenAt.toISOString(),
        };
        // Notify the original sender (flips their bubbles to "read") and the
        // reader's own sibling devices (reconcile local seen state).
        notifier.emitToUser(targetUserIdStr, 'messageSeenUpdate', payload);
        if (authedUserId !== targetUserIdStr) {
          notifier.emitToUser(authedUserId, 'messageSeenUpdate', payload);
        }
      }

      const updatedCount = Number.isFinite(result?.modifiedCount)
        ? result.modifiedCount
        : Number.isFinite(result?.nModified) ? result.nModified : 0;
      return { updatedCount };
    },
  };
}

module.exports = { createMessagingService };
