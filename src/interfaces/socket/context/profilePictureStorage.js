const { persistImageDataUrl } = require('./imageStorage');
const {
  PROFILE_PICTURE_MAX_SIZE,
  PROFILE_PICTURE_MIME_TYPES,
} = require('../../../shared/constants');

/**
 * Persists a base64 profile picture and returns its public URL. Delegates
 * to the shared `persistImageDataUrl` helper which validates MIME, enforces
 * size limits, picks the correct extension, and writes asynchronously.
 *
 * @param {string} base64Image - data URL `data:image/<png|jpeg|webp>;base64,...`
 * @param {string} userId
 * @returns {Promise<string>}
 */
async function saveProfilePicture(base64Image, userId) {
  return persistImageDataUrl({
    dataUrl: base64Image,
    allowedMimeTypes: PROFILE_PICTURE_MIME_TYPES,
    maxSize: PROFILE_PICTURE_MAX_SIZE,
    filenamePrefix: 'profile',
    userId,
  });
}

module.exports = { saveProfilePicture };
