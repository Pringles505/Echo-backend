const path = require('path');
const fs = require('fs');

/**
 * Persists a base64 profile image in the uploads folder and returns a public URL.
 * @param {string} base64Image
 * @param {string} userId
 */
async function saveProfilePicture(base64Image, userId) {
  const uploadDir = path.join(process.cwd(), 'uploads');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
  }
  const filename = `${userId}-${Date.now()}.png`;
  const filePath = path.join(uploadDir, filename);
  const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, '');
  fs.writeFileSync(filePath, base64Data, { encoding: 'base64' });
  return `/uploads/${filename}`;
}

module.exports = { saveProfilePicture };
