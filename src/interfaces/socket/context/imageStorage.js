const path = require('path');
const fs = require('fs/promises');
const { BadRequestError } = require('../../../shared/errors');

const DATA_URL_RE = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/;

const EXT_BY_MIME = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/webp': 'webp',
};

// Throws `BadRequestError` with stable codes so HTTP handlers can map them
// straight to a 400 with a useful `code` field:
//   - `invalid_image`:       not a base64 image data URL
//   - `invalid_image_type`:  MIME type not in `allowedMimeTypes`
//   - `image_too_large`:     decoded size exceeds `maxSize`
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
  const uploadDir = path.join(process.cwd(), 'uploads');
  await fs.mkdir(uploadDir, { recursive: true });
  const filename = `${filenamePrefix}-${userId}-${Date.now()}.${ext}`;
  const filePath = path.join(uploadDir, filename);
  await fs.writeFile(filePath, base64Data, { encoding: 'base64' });
  return `/uploads/${filename}`;
}

module.exports = { persistImageDataUrl };
