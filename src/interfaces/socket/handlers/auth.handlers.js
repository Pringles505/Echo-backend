/**
 * Socket event handlers for authentication (register, login).
 * @module interfaces/socket/handlers/auth
 */

/**
 * @typedef {object} KeyBundle
 * @property {string} publicIdentityKeyX25519 - X25519 identity public key
 * @property {string} publicIdentityKeyEd25519 - Ed25519 identity public key
 * @property {Array} publicSignedPreKey - [signedPreKey, signature]
 * @property {Array} oneTimePreKeys - Array of OPK objects
 */

/**
 * @typedef {object} RegisterPayload
 * @property {string} username - Account identifier
 * @property {string} password - Account password
 * @property {KeyBundle} keyBundle - Signal Protocol keys
 * @property {string} [aboutme] - User bio
 * @property {string} [profilePicture] - Profile picture (base64)
 */

/**
 * @typedef {object} RegisterAckResponse
 * @property {boolean} success - true if successful
 * @property {string} [userId] - User ID if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} LoginPayload
 * @property {string} username - Account identifier
 * @property {string} password - Account password
 */

/**
 * @typedef {object} LoginAckResponse
 * @property {boolean} success - true if authentication succeeded
 * @property {string} [token] - JWT token if successful
 * @property {string} [userId] - User ID if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * Registers Socket.IO handlers for authentication events.
 * Preserves backward-compatible event contracts.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.authService - Authentication application service
 */
function registerAuthSocketHandlers({ socket, authService }) {
  /**
   * 'register' event - Create a new user account.
   * @event register
   * @type {RegisterPayload}
   * @param {RegisterAckResponse} callback - Ack callback
   */
  socket.on('register', async (data, callback) => {
    const { username, password, keyBundle, aboutme, profilePicture } = data;
    const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;

    console.log('Received register:', data);
    console.log('Public Identity Key X25519:', publicIdentityKeyX25519);
    console.log('Public Identity Key Ed25519:', publicIdentityKeyEd25519);

    try {
      const { userId } = await authService.register({
        username,
        password,
        keyBundle: { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys },
        aboutme,
        profilePicture,
      });
      callback({ success: true, userId });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
        callback({ success: false, error: 'Username already taken' });
      } else {
        console.error('Error saving user:', err);
        callback({ success: false, error: 'Registration failed' });
      }
    }
  });

  /**
   * 'login' event - Authenticate and receive JWT token.
   * @event login
   * @type {LoginPayload}
   * @param {LoginAckResponse} callback - Ack callback
   */
  socket.on('login', async (data, callback) => {
    const { username, password } = data;
    console.log('Received login:', data);

    try {
      const result = await authService.login({ username, password });
      callback(result);
    } catch (err) {
      console.error('Error during login:', err);
      callback({ success: false, error: 'Login failed' });
    }
  });
}

module.exports = { registerAuthSocketHandlers };
