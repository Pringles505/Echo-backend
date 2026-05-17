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
  const socketRequestMetadata = () => ({
    ipAddress: socket.handshake?.address || socket.conn?.remoteAddress || null,
    userAgent: socket.handshake?.headers?.['user-agent'] || null,
  });

  /**
   * 'register' event - Create a new user account.
   * @event register
   * @type {RegisterPayload}
   * @param {RegisterAckResponse} callback - Ack callback
   */
  socket.on('register', async (data, callback) => {
    const payload = data && typeof data === 'object' ? data : {};
    const { username, password, keyBundle, aboutme, profilePicture, deviceId, deviceName, platform, userAgent, locale, timezone } = payload;
    if (!keyBundle || typeof keyBundle !== 'object') {
      if (typeof callback === 'function') {
        callback({ success: false, error: 'Missing required fields' });
      }
      return;
    }
    const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;

    console.log('Received register:', data);
    console.log('Public Identity Key X25519:', publicIdentityKeyX25519);
    console.log('Public Identity Key Ed25519:', publicIdentityKeyEd25519);

    try {
      const result = await authService.register({
        username,
        password,
        keyBundle: { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys },
        aboutme,
        profilePicture,
        deviceId,
        deviceName,
        platform,
        userAgent,
        locale,
        timezone,
        requestMetadata: socketRequestMetadata(),
      });
      callback({ success: true, ...result });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern) {
        if (err.keyPattern.username) {
          callback({ success: false, error: 'Username already taken' });
        } else if (err.keyPattern.deviceId) {
          callback({ success: false, error: 'This device is already registered to another account' });
        } else {
          console.error('Error saving user:', err);
          callback({ success: false, error: 'Registration failed' });
        }
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
    const safeAck = (payload) => {
      if (typeof callback === 'function') callback(payload);
    };
    const payload = data && typeof data === 'object' ? data : {};
    const { username, password, deviceId, deviceName, platform, userAgent, locale, timezone } = payload;
    console.log('Received login:', payload);

    try {
      const result = await authService.login({
        username,
        password,
        deviceId,
        deviceName,
        platform,
        userAgent,
        locale,
        timezone,
        requestMetadata: socketRequestMetadata(),
      });
      safeAck(result);
    } catch (err) {
      console.error('Error during login:', err);
      safeAck({ success: false, error: 'Login failed' });
    }
  });
}

module.exports = { registerAuthSocketHandlers };
