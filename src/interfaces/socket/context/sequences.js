/**
 * Build a stable key for a direct conversation.
 * @param {string} userA
 * @param {string} userB
 * @returns {string}
 */
function makeConversationKey(userA, userB) {
  return [String(userA ?? ''), String(userB ?? '')].sort().join('_');
}

/**
 * Creates sequence-boundary services for direct and group conversations.
 * @param {object} deps
 * @param {import('mongoose').Model} deps.Message
 * @param {import('mongoose').Model} deps.MessageSequence
 * @param {import('mongoose').Model} deps.GroupSequence
 */
function createSequenceService({ Message, MessageSequence, GroupSequence }) {
  /**
   * Ensures a conversation sequence exists and is initialized from prior direct messages.
   * @param {string} conversationKey
   * @param {string} userA
   * @param {string} userB
   */
  async function ensureConversationSequence(conversationKey, userA, userB) {
    const existing = await MessageSequence.findOne({ conversationKey }).lean();
    if (existing) return existing;

    const a = String(userA ?? '');
    const b = String(userB ?? '');

    const lastMsg = await Message.findOne({
      $or: [
        { userId: a, targetUserId: b },
        { userId: b, targetUserId: a },
      ],
      messageType: 'text',
      messageNumber: { $type: 'number' },
    })
      .sort({ messageNumber: -1 })
      .select({ messageNumber: 1 })
      .lean();

    const last = Number.isFinite(lastMsg?.messageNumber) ? lastMsg.messageNumber : -1;
    const participants = [a, b].filter(Boolean).sort();

    try {
      return await MessageSequence.create({
        conversationKey,
        participants,
        lastMessageNumber: last,
        updatedAt: new Date(),
        createdAt: new Date(),
      });
    } catch (err) {
      if (err?.code === 11000) {
        return await MessageSequence.findOne({ conversationKey }).lean();
      }
      throw err;
    }
  }

  /**
   * Ensures a sequence row exists for a group.
   * @param {string} groupId
   */
  async function ensureGroupSequence(groupId) {
    const gid = String(groupId ?? '');
    if (!gid) throw new Error('Missing groupId');

    const existing = await GroupSequence.findOne({ groupId: gid }).lean();
    if (existing) return existing;

    try {
      return await GroupSequence.create({
        groupId: gid,
        lastSequenceNumber: -1,
        updatedAt: new Date(),
      });
    } catch (err) {
      if (err?.code === 11000) {
        return await GroupSequence.findOne({ groupId: gid }).lean();
      }
      throw err;
    }
  }

  return { makeConversationKey, ensureConversationSequence, ensureGroupSequence };
}

module.exports = {
  makeConversationKey,
  createSequenceService,
};
