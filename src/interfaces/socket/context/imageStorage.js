const path = require('path');
const fs = require('fs/promises');
const { BadRequestError } = require('../../../shared/errors');
const { UPLOADS_DIR } = require('../../../shared/constants');

const DATA_URL_RE = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/;

const EXT_BY_MIME = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/webp': 'webp',
};

/**
 * Validate, decode, and persist a base64 data URL image.
 *
 * - Parses the actual MIME type from the data URL (does not assume PNG).
 * - Validates the MIME type against an explicit allowlist.
 * - Validates the decoded byte size against a maximum.
 * - Writes the file asynchronously to avoid blocking the event loop on
 *   multi-MB uploads.
 *
 * Throws `BadRequestError` with stable codes so HTTP handlers can map them
 * to 400 responses with a useful `code` field:
 *   - `invalid_image`: not a base64 image data URL
 *   - `invalid_image_type`: MIME type not allowed
 *   - `image_too_large`: decoded size exceeds maxSize
 *
 * @param {object} opts
 * @param {string} opts.dataUrl
 * @param {Array<string>} opts.allowedMimeTypes
 * @param {number} opts.maxSize - max decoded byte size
 * @param {string} opts.filenamePrefix - e.g. 'banner' or 'profile'
 * @param {string} opts.userId
 * @returns {Promise<string>} Public URL `/uploads/<filename>`
 */
async function persistImageDataUrl({
  dataUrl,
  allowedMimeTypes,
  maxSize,
  filenamePrefix,
  userId,
}) {
  if (typeof dataUrl !== 'string') {
    throw new BadRequestError('Image must be a string', 'invalid_image');
  }
  const match = DATA_URL_RE.exec(dataUrl);
  if (!match) {
    throw new BadRequestError('Image must be a base64 data URL', 'invalid_image');
  }
  const [, mimeType, base64Data] = match;
  if (!Array.isArray(allowedMimeTypes) || !allowedMimeTypes.includes(mimeType)) {
    throw new BadRequestError(
      `Unsupported image type: ${mimeType}`,
      'invalid_image_type'
    );
  }

  const sizeBytes = Math.ceil((base64Data.length * 3) / 4);
  if (Number.isFinite(maxSize) && sizeBytes > maxSize) {
    throw new BadRequestError(
      `Image exceeds max size of ${maxSize} bytes`,
      'image_too_large'
    );
  }

  const ext = EXT_BY_MIME[mimeType];
  // Persist under the SAME physical directory served by server.js:
  // server.js -> app.use('/uploads', express.static(path.join(__dirname, 'uploads')))
  // This file lives at src/interfaces/socket/context — go up 4 levels to repo root.
  const uploadDir = path.join(__dirname, '../../../../', UPLOADS_DIR || 'uploads');
  await fs.mkdir(uploadDir, { recursive: true });
  const filename = `${filenamePrefix}-${userId}-${Date.now()}.${ext}`;
  const filePath = path.join(uploadDir, filename);
  await fs.writeFile(filePath, base64Data, { encoding: 'base64' });
  return `/uploads/${filename}`;
}

module.exports = { persistImageDataUrl };
