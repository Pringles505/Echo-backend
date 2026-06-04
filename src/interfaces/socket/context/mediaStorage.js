const path = require('path');
const fs = require('fs/promises');
const { createReadStream } = require('fs');
const { customAlphabet } = require('nanoid');
const { BadRequestError } = require('../../../shared/errors');
const { MEDIA_DIR } = require('../../../shared/constants');

// URL-safe, unguessable blob ids. 24 chars over a 62-symbol alphabet ≈ 142 bits
// of entropy — the id itself is the (weak) capability to fetch the ciphertext,
// and the ciphertext is useless without the per-message key, so this is the
// dominant access control until per-conversation membership checks land.
const ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const makeMediaId = customAlphabet(ID_ALPHABET, 24);
const MEDIA_ID_RE = /^[A-Za-z0-9]{8,64}$/;

// This file lives at src/interfaces/socket/context — go up 4 levels to repo
// root, mirroring imageStorage.js. The dir is intentionally NOT under the
// public `/uploads` static mount: blobs are opaque ciphertext fetched only via
// the authenticated GET /media/:id route.
function mediaDirPath() {
  return path.join(__dirname, '../../../../', MEDIA_DIR || 'media');
}

function isValidMediaId(mediaId) {
  return typeof mediaId === 'string' && MEDIA_ID_RE.test(mediaId);
}

/**
 * Persist an opaque encrypted media blob and return its id.
 * @param {Buffer|Uint8Array} bytes - ciphertext container (echo-blob-v1)
 * @returns {Promise<string>} mediaId
 */
async function saveMediaBlob(bytes) {
  if (!bytes || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) || bytes.length === 0) {
    throw new BadRequestError('Media body must be non-empty binary', 'invalid_media');
  }
  const dir = mediaDirPath();
  await fs.mkdir(dir, { recursive: true });
  const mediaId = makeMediaId();
  await fs.writeFile(path.join(dir, mediaId), bytes);
  return mediaId;
}

/**
 * Resolve the absolute path of a stored blob, guarding against traversal.
 * Returns null when the id is malformed or the blob does not exist.
 * @param {string} mediaId
 * @returns {Promise<string|null>}
 */
async function resolveMediaBlobPath(mediaId) {
  if (!isValidMediaId(mediaId)) return null;
  const filePath = path.join(mediaDirPath(), mediaId);
  try {
    const stat = await fs.stat(filePath);
    return stat.isFile() ? filePath : null;
  } catch {
    return null;
  }
}

/**
 * Open a read stream for a stored blob, or null if absent/invalid.
 * @param {string} mediaId
 * @returns {Promise<{ stream: import('fs').ReadStream, size: number }|null>}
 */
async function openMediaBlobStream(mediaId) {
  const filePath = await resolveMediaBlobPath(mediaId);
  if (!filePath) return null;
  const { size } = await fs.stat(filePath);
  return { stream: createReadStream(filePath), size };
}

module.exports = { saveMediaBlob, resolveMediaBlobPath, openMediaBlobStream, isValidMediaId };
