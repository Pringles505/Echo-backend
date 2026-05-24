// Stable key for a direct conversation.
//   - Legacy account-level sessions: `{userA}_{userB}` with ids sorted.
//   - Per-device fanout sessions:    `{userA@devA}_{userB@devB}` so multi-
//     device sends don't race each other's messageNumber sequences.
//   - Mixed primary/secondary: the side without a deviceId falls back to
//     its bare user id so the key stays deterministic.
function makeConversationKey(userA, userB, deviceIds = {}) {
  const sideA = deviceIds?.devA ? `${String(userA ?? '')}@${String(deviceIds.devA)}` : String(userA ?? '');
  const sideB = deviceIds?.devB ? `${String(userB ?? '')}@${String(deviceIds.devB)}` : String(userB ?? '');
  return [sideA, sideB].sort().join('_');
}

function createSequenceService({ Message, MessageSequence, GroupSequence }) {
  // Backfills `lastMessageNumber` from prior direct messages when the sequence
  // row is first created, so newly-introduced sequencing doesn't reset the
  // counter for existing conversations.
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
