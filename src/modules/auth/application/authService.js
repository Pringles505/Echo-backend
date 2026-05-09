const { customAlphabet } = require('nanoid');

/**
 * @typedef {object} KeyBundle
 * @property {string} publicIdentityKeyX25519 - X25519 identity public key (base64)
 * @property {string} publicIdentityKeyEd25519 - Ed25519 identity public key (base64)
 * @property {Array} publicSignedPreKey - [base64 SPK, signature]
 * @property {Array} oneTimePreKeys - Array of OPK objects
 */

/**
 * @typedef {object} RegisterInput
 * @property {string} username - User account identifier
 * @property {string} password - User password (will be hashed)
 * @property {KeyBundle} keyBundle - Signal Protocol key bundle
 * @property {string} [aboutme] - User bio
 * @property {string} [profilePicture] - Profile picture as base64
 */

/**
 * @typedef {object} RegisterResult
 * @property {string} userId - Generated 5-character user ID
 */

/**
 * @typedef {object} LoginInput
 * @property {string} username - Username to authenticate
 * @property {string} password - Password to verify
 */

/**
 * @typedef {object} LoginResult
 * @property {boolean} success - Authentication result
 * @property {string} [token] - JWT token if successful
 * @property {string} [userId] - User ID if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * Application service for authentication use cases.
 * Handles user registration and login with Signal Protocol key setup.
 *
 * @param {object} deps - Service dependencies
 * @param {*} deps.User - Mongoose User model
 * @param {*} deps.bcrypt - Bcryptjs module for password hashing
 * @param {*} deps.jwt - Jsonwebtoken module for token generation
 * @param {function} deps.normalizeOneTimePreKeysPayload - OPK normalization function
 * @param {number} deps.OPK_MAX_STORED - Maximum OPKs per user
 * @returns {object} Service with register and login methods
 */
function createAuthService({ User, bcrypt, jwt, normalizeOneTimePreKeysPayload, OPK_MAX_STORED }) {
  return {
    /**
     * Register a new user account.
     * @param {RegisterInput} input
     * @returns {Promise<RegisterResult>}
     * @throws {Error} If username is duplicate or validation fails
     */
    async register({ username, password, keyBundle, aboutme, profilePicture }) {
      const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;
      const [signedPreKey, signature] = publicSignedPreKey;

      const hashedPassword = await bcrypt.hash(password, 10);
      const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
      const id = nanoid();
      const normalizedOpks = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_MAX_STORED);

      const user = new User({
        id,
        username,
        hashedPassword,
        publicIdentityKeyX25519,
        publicIdentityKeyEd25519,
        signedPreKey,
        signature,
        signedPreKeyId: 0,
        oneTimePreKeys: normalizedOpks,
        aboutme: typeof aboutme === 'string' ? aboutme : '',
        profilePicture: typeof profilePicture === 'string' ? profilePicture : '',
      });

      await user.save();
      return { userId: id };
    },

    /**
     * Authenticate user and generate JWT token.
     * @param {LoginInput} input
     * @returns {Promise<LoginResult>}
     */
    async login({ username, password }) {
      const user = await User.findOne({ username });
      if (!user) return { success: false, error: 'Invalid username or password' };

      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) return { success: false, error: 'Invalid username or password' };

      const token = jwt.sign(
        { id: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
      );

      return { success: true, token, userId: user.id };
    },
  };
}

module.exports = { createAuthService };
