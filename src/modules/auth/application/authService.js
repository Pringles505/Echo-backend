const crypto = require('crypto');
const { customAlphabet } = require('nanoid');
const {
  ACCESS_TOKEN_TTL,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_BYTES,
  BCRYPT_SALT_ROUNDS,
  DEVICE_TOKEN_TTL,
} = require('../../../shared/constants');
const { UnauthorizedError, BadRequestError } = require('../../../shared/errors');

/**
 * Hash a refresh token with SHA-256. We store the hash, never the plain token.
 */
function hashToken(plain) {
  return crypto.createHash('sha256').update(plain, 'utf8').digest('hex');
}

function generatePlainRefreshToken() {
  return crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('hex');
}

function signAccessToken(jwt, user, secret, device = {}) {
  const payload = { id: user.id, username: user.username };
  if (device.deviceId) payload.deviceId = device.deviceId;
  if (device.deviceUserId) payload.deviceUserId = device.deviceUserId;
  if (device.platform) payload.platform = device.platform;
  return jwt.sign(payload, secret, { expiresIn: ACCESS_TOKEN_TTL });
}

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

/**
 * Application service for authentication use cases.
 */
function createAuthService({
  User,
  RefreshToken,
  Device,
  bcrypt,
  jwt,
  jwtSecret,
  normalizeOneTimePreKeysPayload,
  OPK_MAX_STORED,
}) {
  if (!User) throw new Error('createAuthService requires User model');
  if (!bcrypt) throw new Error('createAuthService requires bcrypt');
  if (!jwt) throw new Error('createAuthService requires jwt');
  const secret = jwtSecret || process.env.JWT_SECRET;
  if (!secret || typeof secret !== 'string' || secret.length === 0) {
    throw new Error('createAuthService requires a non-empty jwtSecret (or JWT_SECRET env var)');
  }

  async function issueRefreshToken({ userId, deviceId, deviceUserId, platform, ip, userAgent }) {
    const plain = generatePlainRefreshToken();
    const tokenHash = hashToken(plain);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000);
    await RefreshToken.create({
      tokenHash,
      userId,
      deviceId: deviceId || null,
      deviceUserId: deviceUserId || null,
      platform: platform || null,
      expiresAt,
      revoked: false,
      ip: ip || null,
      userAgent: userAgent || null,
    });
    return { plain, tokenHash };
  }

  return {
    /**
     * Register a new user account.
     * Refresh tokens are not issued here; caller must POST /auth/login.
     */
    async register({
      username,
      password,
      keyBundle,
      aboutme,
      profilePicture,
      deviceId,
      deviceName,
      platform,
      userAgent,
      locale,
      timezone,
      requestMetadata,
    }) {
      const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } =
        keyBundle;
      const [signedPreKey, signature] = publicSignedPreKey;

      const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
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
        const deviceIdNanoid = customAlphabet(
          'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
          24
        );
        // The client passes the `deviceId` it has cached in localStorage. In dev
        // (and the wild) the same browser is regularly used to register multiple
        // accounts in a row — `getOrCreateDeviceId()` returns the SAME id every
        // time, so the second registration would collide on Device.deviceId
        // (E11000) and the previous catch ran `user.deleteOne()` silently. The
        // user saw a 500 with no clear cause and a brand-new account vanished.
        //
        // Fix: on a deviceId collision, mint a fresh server-side deviceId and
        // retry the insert. The new id is returned to the caller so the client
        // can replace its local copy via `storage.set(KEYS.DEVICE_ID, …)`. The
        // user is NEVER rolled back for an avoidable transient collision.
        let resolvedDeviceId = deviceId;
        let attempts = 0;
        const MAX_DEVICE_ID_RETRIES = 4;
        while (true) {
          try {
            await Device.create({
              deviceId: resolvedDeviceId,
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
            break;
          } catch (deviceErr) {
            const isDuplicateDeviceId =
              deviceErr?.code === 11000 && deviceErr?.keyPattern?.deviceId;
            if (isDuplicateDeviceId && attempts < MAX_DEVICE_ID_RETRIES) {
              attempts += 1;
              resolvedDeviceId = `device-${deviceIdNanoid()}`;
              continue;
            }
            // Anything else (validation, network, exhausted retries) is a real
            // failure — roll back the User and surface the original error.
            await user.deleteOne().catch(() => {});
            throw deviceErr;
          }
        }
        await User.updateOne({ id }, { $addToSet: { devices: primaryDeviceUserId } });
        return { userId: id, deviceId: resolvedDeviceId, deviceUserId: primaryDeviceUserId };
      }

      return { userId: id };
    },

    /**
     * Authenticate user, verify the caller's device, and issue access/refresh tokens.
     */
    async login({
      username,
      password,
      deviceId,
      deviceName,
      platform,
      userAgent,
      locale,
      timezone,
      ip,
      requestMetadata,
    } = {}) {
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

      await Device.updateOne(
        { deviceId },
        {
          $set: {
            ...metadataSet({ deviceName, platform, userAgent, locale, timezone }, requestMetadata),
            lastSeen: new Date(),
          },
        }
      );

      const devicePayload = {
        deviceId,
        deviceUserId: device.deviceUserId,
        platform: platform || device.platform || null,
      };
      const token = signAccessToken(jwt, user, secret, devicePayload);

      let refreshToken = null;
      if (RefreshToken && typeof RefreshToken.create === 'function') {
        const issued = await issueRefreshToken({
          userId: user.id,
          ...devicePayload,
          ip,
          userAgent: requestMetadata?.userAgent || userAgent,
        });
        refreshToken = issued.plain;
      }

      return {
        success: true,
        token,
        refreshToken,
        userId: user.id,
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        deviceId,
        deviceUserId: device.deviceUserId,
      };
    },

    /**
     * Exchange a valid refresh token for a fresh access+refresh pair.
     */
    async refresh({ refreshToken, ip, userAgent } = {}) {
      if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
        throw new BadRequestError('refreshToken is required', 'validation_error');
      }
      if (!RefreshToken || typeof RefreshToken.findOne !== 'function') {
        throw new Error('createAuthService.refresh requires RefreshToken model');
      }

      const tokenHash = hashToken(refreshToken);
      const stored = await RefreshToken.findOne({ tokenHash });
      if (!stored) {
        throw new UnauthorizedError('Refresh token is invalid', 'refresh_token_invalid');
      }

      if (stored.revoked) {
        await RefreshToken.updateMany(
          { userId: stored.userId, revoked: false },
          { $set: { revoked: true, revokedAt: new Date(), reusedAt: new Date() } }
        );
        throw new UnauthorizedError('Refresh token reuse detected', 'refresh_token_reused');
      }

      if (stored.expiresAt instanceof Date && stored.expiresAt.getTime() <= Date.now()) {
        throw new UnauthorizedError('Refresh token has expired', 'refresh_token_expired');
      }

      const user = await User.findOne({ id: stored.userId });
      if (!user) {
        throw new UnauthorizedError('User no longer exists', 'user_not_found');
      }

      const devicePayload = {
        deviceId: stored.deviceId || null,
        deviceUserId: stored.deviceUserId || null,
        platform: stored.platform || null,
      };
      if (Device && devicePayload.deviceId) {
        const device = await Device.findOne({ deviceId: devicePayload.deviceId }).lean();
        if (!device || device.isRevoked || String(device.parentUserId) !== String(user.id)) {
          throw new UnauthorizedError('Device is no longer authorized', 'device_revoked');
        }
        devicePayload.deviceUserId = device.deviceUserId;
        devicePayload.platform = devicePayload.platform || device.platform || null;
      }

      const issued = await issueRefreshToken({
        userId: stored.userId,
        ...devicePayload,
        ip,
        userAgent,
      });
      stored.revoked = true;
      stored.revokedAt = new Date();
      stored.replacedBy = issued.tokenHash;
      await stored.save();

      const token = signAccessToken(jwt, user, secret, devicePayload);
      return {
        token,
        refreshToken: issued.plain,
        userId: user.id,
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        deviceId: devicePayload.deviceId || undefined,
        deviceUserId: devicePayload.deviceUserId || undefined,
      };
    },

    /**
     * Revoke a refresh token.
     */
    async logout({ refreshToken, userId } = {}) {
      if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
        throw new BadRequestError('refreshToken is required', 'validation_error');
      }
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (!RefreshToken || typeof RefreshToken.findOneAndUpdate !== 'function') {
        throw new Error('createAuthService.logout requires RefreshToken model');
      }
      const tokenHash = hashToken(refreshToken);
      await RefreshToken.findOneAndUpdate(
        { tokenHash, userId },
        { $set: { revoked: true, revokedAt: new Date() } }
      );
      return { ok: true };
    },

    issueDeviceJwt({ userId, username, deviceId, deviceUserId, platform }) {
      const payload = { id: userId, username };
      if (deviceId) payload.deviceId = deviceId;
      if (deviceUserId) payload.deviceUserId = deviceUserId;
      if (platform) payload.platform = platform;
      return jwt.sign(payload, secret, { expiresIn: DEVICE_TOKEN_TTL });
    },

    async upsertDeviceRecord({
      userId,
      deviceId,
      deviceName,
      platform,
      userAgent,
      locale,
      timezone,
      requestMetadata,
      provisionedVia,
      allowReenable = false,
    }) {
      if (!Device) return null;
      const user = await User.findOne({ id: userId }).lean();
      if (!user) return null;
      let resolvedDeviceId = deviceId;
      let existing = await Device.findOne({ deviceId: resolvedDeviceId });
      if (existing) {
        if (String(existing.parentUserId) !== String(userId)) {
          const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 24);
          resolvedDeviceId = `device-${nanoid()}`;
          existing = null;
        } else if (existing.isRevoked && !allowReenable) {
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

module.exports = { createAuthService, hashToken };
