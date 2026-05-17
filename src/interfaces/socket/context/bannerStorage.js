const { persistImageDataUrl } = require('./imageStorage');
const {
  BANNER_MAX_SIZE,
  BANNER_MIME_TYPES,
} = require('../../../shared/constants');

/**
 * Persists a base64 banner image and returns its public URL. Delegates to
 * the shared `persistImageDataUrl` helper which validates MIME, enforces
 * size limits, picks the correct extension, and writes asynchronously.
 *
 * @param {string} base64Image - data URL `data:image/<png|jpeg|webp>;base64,...`
 * @param {string} userId
 * @returns {Promise<string>}
 */
async function saveBanner(base64Image, userId) {
  return persistImageDataUrl({
    dataUrl: base64Image,
    allowedMimeTypes: BANNER_MIME_TYPES,
    maxSize: BANNER_MAX_SIZE,
    filenamePrefix: 'banner',
    userId,
  });
}

module.exports = { saveBanner };
