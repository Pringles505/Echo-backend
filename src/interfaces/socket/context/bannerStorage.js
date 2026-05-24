const { persistImageDataUrl } = require('./imageStorage');
const {
  BANNER_MAX_SIZE,
  BANNER_MIME_TYPES,
} = require('../../../shared/constants');

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
