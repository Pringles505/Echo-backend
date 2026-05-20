/**
 * Build a stable key for a direct conversation.
 *
 * Account-level (legacy single-device) sessions key by `{userA}_{userB}`
 * with the user ids sorted. Per-device fanout sessions key by
 * `{userA@devA}_{userB@devB}` so multi-device sends don't race each
 * other's messageNumber sequences. When only one side has a deviceId
 * (mixed primary/secondary), the missing side falls back to its bare
 * user id so the key is still deterministic.
 *
 * @param {string} userA
 * @param {string} userB
 * @param {{ devA?: string|null, devB?: string|null }} [deviceIds]
 * @returns {string}
 */
function makeConversationKey(userA, userB, deviceIds = {}) {
  const sideA = deviceIds?.devA ? `${String(userA ?? '')}@${String(deviceIds.devA)}` : String(userA ?? '');
  const sideB = deviceIds?.devB ? `${String(userB ?? '')}@${String(deviceIds.devB)}` : String(userB ?? '');
  return [sideA, sideB].sort().join('_');
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
