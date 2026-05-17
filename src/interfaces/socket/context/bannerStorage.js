const path = require('path');
const fs = require('fs');

/**
 * Persists a base64 banner image in the uploads folder and returns a public URL.
 * Mirrors `profilePictureStorage.saveProfilePicture` but uses a `banner-` prefix
 * so banners and profile pictures live side-by-side in the same `/uploads`
 * static mount without colliding.
 *
 * @param {string} base64Image - Data URL of form `data:image/...;base64,...`
 * @param {string} userId
 * @returns {Promise<string>} Public URL like `/uploads/banner-USERID-TS.png`
 */
async function saveBanner(base64Image, userId) {
  const uploadDir = path.join(process.cwd(), 'uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
  }
  const filename = `banner-${userId}-${Date.now()}.png`;
  const filePath = path.join(uploadDir, filename);
  const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, '');
  fs.writeFileSync(filePath, base64Data, { encoding: 'base64' });
  return `/uploads/${filename}`;
}

module.exports = { saveBanner };
