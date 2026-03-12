const OPK_LOW_WATERMARK = 50;
const OPK_TARGET_COUNT = 100;
const OPK_MAX_STORED = 500;
const OPK_UPLOAD_MAX = 200;

function normalizeOneTimePreKeysPayload(oneTimePreKeys, max = OPK_UPLOAD_MAX) {
  const incoming =
    Array.isArray(oneTimePreKeys)
      ? oneTimePreKeys
          .filter((k) => k && typeof k === 'object')
          // Client may send { opkId, publicKey } (preferred) or { opkId, opkPub } (legacy).
          .map((k) => ({ opkId: String(k.opkId ?? ''), opkPub: String(k.opkPub ?? k.publicKey ?? '') }))
          .filter((k) => k.opkId && k.opkPub)
      : [];

  return incoming.slice(0, Math.max(0, max | 0));
}

function computeOpkReplenishNeeded(currentCount) {
  const count = Number.isFinite(currentCount) ? currentCount : 0;
  if (count >= OPK_LOW_WATERMARK) return 0;
  return Math.max(0, Math.min(OPK_TARGET_COUNT - count, OPK_UPLOAD_MAX));
}

function dedupeIncomingOpks(existingOpks, incomingOpks) {
  const existingIds = new Set(
    Array.isArray(existingOpks) ? existingOpks.map((k) => String(k?.opkId ?? '')) : []
  );

  const unique = [];
  for (const k of Array.isArray(incomingOpks) ? incomingOpks : []) {
    const id = String(k?.opkId ?? '');
    if (!id || existingIds.has(id)) continue;
    existingIds.add(id);
    unique.push({ opkId: id, opkPub: String(k?.opkPub ?? '') });
  }
  return unique;
}

function capToRemainingCapacity(currentCount, incomingOpks, maxStored = OPK_MAX_STORED) {
  const count = Number.isFinite(currentCount) ? currentCount : 0;
  const capacity = Math.max(0, (maxStored | 0) - count);
  return (Array.isArray(incomingOpks) ? incomingOpks : []).slice(0, capacity);
}

function estimateOpkCountAfterConsume(preConsumeCount) {
  const count = Number.isFinite(preConsumeCount) ? preConsumeCount : 0;
  return Math.max(count - 1, 0);
}

module.exports = {
  OPK_LOW_WATERMARK,
  OPK_TARGET_COUNT,
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  normalizeOneTimePreKeysPayload,
  computeOpkReplenishNeeded,
  dedupeIncomingOpks,
  capToRemainingCapacity,
  estimateOpkCountAfterConsume,
};

