const test = require('node:test');
const assert = require('node:assert/strict');

const {
  OPK_LOW_WATERMARK,
  OPK_TARGET_COUNT,
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  normalizeOneTimePreKeysPayload,
  computeOpkReplenishNeeded,
  dedupeIncomingOpks,
  capToRemainingCapacity,
  estimateOpkCountAfterConsume,
} = require('../opkPolicy');

test('normalizeOneTimePreKeysPayload accepts {opkId, publicKey} and {opkId, opkPub}', () => {
  const out = normalizeOneTimePreKeysPayload(
    [
      { opkId: 'a', publicKey: 'PUB_A' },
      { opkId: 'b', opkPub: 'PUB_B' },
      { opkId: 'c', publicKey: '' }, // invalid
      null,
      'nope',
    ],
    10
  );

  assert.deepEqual(out, [
    { opkId: 'a', opkPub: 'PUB_A' },
    { opkId: 'b', opkPub: 'PUB_B' },
  ]);
});

test('normalizeOneTimePreKeysPayload enforces max', () => {
  const out = normalizeOneTimePreKeysPayload(
    [
      { opkId: '1', publicKey: 'P1' },
      { opkId: '2', publicKey: 'P2' },
      { opkId: '3', publicKey: 'P3' },
    ],
    2
  );
  assert.equal(out.length, 2);
  assert.deepEqual(out.map((k) => k.opkId), ['1', '2']);
});

test('computeOpkReplenishNeeded returns 0 at/above low watermark', () => {
  assert.equal(computeOpkReplenishNeeded(OPK_LOW_WATERMARK), 0);
  assert.equal(computeOpkReplenishNeeded(OPK_LOW_WATERMARK + 1), 0);
});

test('computeOpkReplenishNeeded returns bounded needed below low watermark', () => {
  assert.equal(
    computeOpkReplenishNeeded(OPK_LOW_WATERMARK - 1),
    Math.min(OPK_TARGET_COUNT - (OPK_LOW_WATERMARK - 1), OPK_UPLOAD_MAX)
  );

  assert.equal(computeOpkReplenishNeeded(0), Math.min(OPK_TARGET_COUNT, OPK_UPLOAD_MAX));
});

test('dedupeIncomingOpks removes duplicates by opkId', () => {
  const existing = [{ opkId: 'dup', opkPub: 'X' }];
  const incoming = [
    { opkId: 'dup', opkPub: 'Y' },
    { opkId: 'new', opkPub: 'Z' },
  ];

  const out = dedupeIncomingOpks(existing, incoming);
  assert.deepEqual(out, [{ opkId: 'new', opkPub: 'Z' }]);
});

test('capToRemainingCapacity respects OPK_MAX_STORED', () => {
  const currentCount = OPK_MAX_STORED - 1;
  const incoming = [
    { opkId: '1', opkPub: 'P1' },
    { opkId: '2', opkPub: 'P2' },
  ];

  const out = capToRemainingCapacity(currentCount, incoming, OPK_MAX_STORED);
  assert.deepEqual(out, [{ opkId: '1', opkPub: 'P1' }]);
});

test('estimateOpkCountAfterConsume never goes negative', () => {
  assert.equal(estimateOpkCountAfterConsume(0), 0);
  assert.equal(estimateOpkCountAfterConsume(1), 0);
  assert.equal(estimateOpkCountAfterConsume(5), 4);
});

