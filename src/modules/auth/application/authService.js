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
function cleanString(value, maxLength = 512) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

function normalizeIp(ip) {
  const value = cleanString(ip, 128);
  return value ? value.replace(/^::ffff:/, '') : null;
}

function isPrivateIp(ip) {
  return Boolean(
    ip &&
      (ip === '127.0.0.1' ||
        ip === '::1' ||
        ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
        ip.startsWith('fc') ||
        ip.startsWith('fd') ||
        ip.startsWith('fe80:'))
  );
}

function ipLocationLabel(ip) {
  if (!ip) return null;
  if (ip === '127.0.0.1' || ip === '::1') return 'Localhost';
  if (isPrivateIp(ip)) return 'Private network';
  return 'Public IP';
}

function metadataSet(input = {}, requestMetadata = {}) {
  const ipAddress = normalizeIp(requestMetadata.ipAddress || input.ipAddress);
  const metadata = {
    deviceName: cleanString(input.deviceName, 120),
    platform: cleanString(input.platform, 80),
    userAgent: cleanString(requestMetadata.userAgent || input.userAgent, 512),
    ipAddress,
    ipLocation: cleanString(input.ipLocation, 120) || ipLocationLabel(ipAddress),
    locale: cleanString(input.locale, 40),
    timezone: cleanString(input.timezone, 80),
  };
  return Object.fromEntries(Object.entries(metadata).filter(([, value]) => value != null));
}

async function nextSecondaryDeviceUserId(Device, User, mainUserId) {
  const digits = customAlphabet('0123456789', 8);
  let candidate = `${mainUserId}_${digits()}`;
  while (await Device.exists({ deviceUserId: candidate }) || await User.exists({ id: candidate })) {
    candidate = `${mainUserId}_${digits()}`;
  }
  return candidate;
}

function createAuthService({ User, Device, bcrypt, jwt, normalizeOneTimePreKeysPayload, OPK_MAX_STORED }) {
  return {
    /**
     * Register a new user account.
     * @param {RegisterInput} input
     * @returns {Promise<RegisterResult>}
     * @throws {Error} If username is duplicate or validation fails
     */
    async register({ username, password, keyBundle, aboutme, profilePicture, deviceId, deviceName, platform, userAgent, locale, timezone, requestMetadata }) {
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

      if (Device && deviceId) {
        const primaryDeviceUserId = id;
        try {
          await Device.create({
            deviceId,
            parentUserId: id,
            deviceUserId: primaryDeviceUserId,
            deviceName: deviceName || 'Primary device',
            ...metadataSet({ deviceName, platform, userAgent, locale, timezone }, requestMetadata),
            isPrimary: true,
            isRevoked: false,
            publicIdentityKeyX25519,
            publicIdentityKeyEd25519,
            signedPreKey,
            signedPreKeySignature: signature,
            provisionedVia: 'registration',
            lastSeen: new Date(),
          });
        } catch (deviceErr) {
          await user.deleteOne().catch(() => {});
          throw deviceErr;
        }
        await User.updateOne({ id }, { $addToSet: { devices: primaryDeviceUserId } });
        return { userId: id, deviceId, deviceUserId: primaryDeviceUserId };
      }

      return { userId: id };
    },

    /**
     * Authenticate user and generate JWT token.
     *
     * A device can only obtain a session through registration (which creates
     * its primary Device row) or by pairing/syncing with an existing account.
     * Password login is therefore restricted to devices that are already
     * registered for the target user and have not been revoked.
     *
     * @param {LoginInput} input
     * @returns {Promise<LoginResult>}
     */
    async login({ username, password, deviceId, deviceName, platform, userAgent, locale, timezone, requestMetadata }) {
      const user = await User.findOne({ username });
      if (!user) return { success: false, error: 'Invalid username or password' };

      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) return { success: false, error: 'Invalid username or password' };

      if (!Device) {
        return { success: false, error: 'Device registration is required', code: 'device_required' };
      }
      if (!deviceId) {
        return {
          success: false,
          error: 'This device is not paired with the account. Sync it from an existing device first.',
          code: 'device_required',
        };
      }

      const device = await Device.findOne({ deviceId }).lean();
      if (!device) {
        return {
          success: false,
          error: 'This device is not paired with the account. Sync it from an existing device first.',
          code: 'device_not_registered',
        };
      }
      if (String(device.parentUserId) !== String(user.id)) {
        return {
          success: false,
          error: 'This device belongs to a different account.',
          code: 'device_forbidden',
        };
      }
      if (device.isRevoked) {
        return {
          success: false,
          error: 'This device has been revoked. Sync it again from an authorized device to restore access.',
          code: 'device_revoked',
        };
      }

      // Refresh metadata + lastSeen, but never re-enable a revoked record here.
      await Device.updateOne(
        { deviceId },
        { $set: { ...metadataSet({ deviceName, platform, userAgent, locale, timezone }, requestMetadata), lastSeen: new Date() } }
      );

      const payload = {
        id: user.id,
        username: user.username,
        deviceId,
        deviceUserId: device.deviceUserId,
      };
      if (platform) payload.platform = platform;

      const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

      return {
        success: true,
        token,
        userId: user.id,
        deviceId,
        deviceUserId: device.deviceUserId,
      };
    },

    issueDeviceJwt({ userId, username, deviceId, deviceUserId, platform }) {
      const payload = { id: userId, username };
      if (deviceId) payload.deviceId = deviceId;
      if (deviceUserId) payload.deviceUserId = deviceUserId;
      if (platform) payload.platform = platform;
      return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' });
    },

    async upsertDeviceRecord({ userId, deviceId, deviceName, platform, userAgent, locale, timezone, requestMetadata, provisionedVia, allowReenable = false }) {
      if (!Device) return null;
      const user = await User.findOne({ id: userId }).lean();
      if (!user) return null;
      let resolvedDeviceId = deviceId;
      let existing = await Device.findOne({ deviceId: resolvedDeviceId });
      if (existing) {
        // A deviceId already owned by a different user must get a fresh id —
        // we never let one user's device record alias another's.
        if (String(existing.parentUserId) !== String(userId)) {
          const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 24);
          resolvedDeviceId = `device-${nanoid()}`;
          existing = null;
        } else if (existing.isRevoked && !allowReenable) {
          // Same user, but the device was kicked. Caller is not the QR sync
          // flow, so we refuse to silently re-enable; assign a fresh deviceId
          // for the new context instead of bringing the revoked record back.
          const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 24);
          resolvedDeviceId = `device-${nanoid()}`;
          existing = null;
        }
      }

      if (existing) {
        existing.lastSeen = new Date();
        if (existing.isRevoked && allowReenable) {
          existing.isRevoked = false;
        }
        Object.assign(existing, metadataSet({ deviceName, platform, userAgent, locale, timezone }, requestMetadata));
        await existing.save();
        await User.updateOne({ id: userId }, { $addToSet: { devices: existing.deviceUserId } });
        return { deviceId: resolvedDeviceId, deviceUserId: existing.deviceUserId, created: false };
      }
      const deviceUserId = await nextSecondaryDeviceUserId(Device, User, user.id);
      await Device.create({
        deviceId: resolvedDeviceId,
        parentUserId: userId,
        deviceUserId,
        deviceName: deviceName || platform || 'New device',
        ...metadataSet({ deviceName, platform, userAgent, locale, timezone }, requestMetadata),
        isPrimary: false,
        isRevoked: false,
        provisionedVia: provisionedVia || 'device-sync',
        lastSeen: new Date(),
      });
      await User.updateOne({ id: userId }, { $addToSet: { devices: deviceUserId } });
      return { deviceId: resolvedDeviceId, deviceUserId, created: true };
    },
  };
}

module.exports = { createAuthService };
