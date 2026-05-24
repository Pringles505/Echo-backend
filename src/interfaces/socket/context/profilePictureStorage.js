const { persistImageDataUrl } = require('./imageStorage');
const {
  PROFILE_PICTURE_MAX_SIZE,
  PROFILE_PICTURE_MIME_TYPES,
} = require('../../../shared/constants');

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
