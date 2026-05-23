const crypto = require('node:crypto');
const { customAlphabet } = require('nanoid');
const {
  BadRequestError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
} = require('../../../shared/errors');
const {
  PAIRING_SESSION_TTL_MS,
  PAIRING_CODE_LENGTH,
} = require('../../../shared/constants');

const PAIRING_TTL_MS = PAIRING_SESSION_TTL_MS;

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
    platform: cleanString(input.platform, 80),
    userAgent: cleanString(requestMetadata.userAgent || input.userAgent, 512),
    ipAddress,
    ipLocation: cleanString(input.ipLocation, 120) || ipLocationLabel(ipAddress),
    locale: cleanString(input.locale, 40),
    timezone: cleanString(input.timezone, 80),
  };
  return Object.fromEntries(Object.entries(metadata).filter(([, value]) => value != null));
}

function createPairingService({ PairingSession, Device, User, authService }) {
  // 32-character alphabet (Crockford-ish: no 0/O/1/I/L) × PAIRING_CODE_LENGTH chars
  //   8 chars  → ~40 bits entropy (>= the 8-alphanumeric floor requested by audit)
  //   12 chars → ~60 bits, recommended when surfaced as a typed code
  // Enforced floor of 8 lives in shared/constants.js.
  const nanoid = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', PAIRING_CODE_LENGTH);

  function ensureActive(session) {
    if (!session) throw new NotFoundError('Pairing session not found', 'pairing_not_found');
    if (new Date(session.expiresAt) <= new Date()) {
      throw new ConflictError('Pairing session expired', 'pairing_expired');
    }
    if (['approved', 'rejected', 'expired'].includes(session.status)) {
      throw new ConflictError(`Pairing session is ${session.status}`, 'pairing_inactive');
    }
  }

  async function nextDeviceUserId(username) {
    const escapedUsername = username.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let suffix = await Device.countDocuments({
      deviceUserId: new RegExp(`^${escapedUsername}_x\\d+$`),
    }) + 1;

    while (await Device.exists({ deviceUserId: `${username}_x${suffix}` })) {
      suffix += 1;
    }

    return `${username}_x${suffix}`;
  }

  return {
    async createSession({ parentUserId, primaryDeviceId, serverUrl }) {
      const user = await User.findOne({ id: parentUserId }).lean();
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      const sessionId = nanoid();
      const challenge = crypto.randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + PAIRING_TTL_MS);

      await PairingSession.create({
        sessionId,
        parentUserId,
        primaryDeviceId,
        challenge,
        expiresAt,
        serverUrl: serverUrl || null,
      });

      return { sessionId, parentUserId, primaryDeviceId, challenge, expiresAt, serverUrl };
    },

    async getSession({ sessionId }) {
      const s = await PairingSession.findOne({ sessionId }).lean();
      if (!s) throw new NotFoundError('Pairing session not found', 'pairing_not_found');
      return {
        sessionId: s.sessionId,
        status: s.status,
        parentUserId: s.parentUserId,
        primaryDeviceId: s.primaryDeviceId,
        expiresAt: s.expiresAt,
        newDeviceId: s.newDeviceId,
        newDeviceName: s.newDeviceName,
        newDevicePublicIdentityKeyX25519: s.newDevicePublicIdentityKeyX25519,
        newDevicePublicIdentityKeyEd25519: s.newDevicePublicIdentityKeyEd25519,
      };
    },

    async submitRequest({
      sessionId,
      newDeviceId,
      newDeviceName,
      newDevicePublicIdentityKeyX25519,
      newDevicePublicIdentityKeyEd25519,
      newDeviceSignedPreKey,
      newDeviceSignedPreKeySignature,
      challengeResponse,
      platform,
      userAgent,
      locale,
      timezone,
      requestMetadata,
    }) {
      if (!newDeviceId) throw new BadRequestError('Missing newDeviceId');
      if (!newDevicePublicIdentityKeyX25519) throw new BadRequestError('Missing newDevicePublicIdentityKeyX25519');
      if (!newDevicePublicIdentityKeyEd25519) throw new BadRequestError('Missing newDevicePublicIdentityKeyEd25519');
      if (!newDeviceSignedPreKey) throw new BadRequestError('Missing newDeviceSignedPreKey');
      if (!newDeviceSignedPreKeySignature) throw new BadRequestError('Missing newDeviceSignedPreKeySignature');

      const session = await PairingSession.findOne({ sessionId });
      ensureActive(session);

      if (session.status !== 'pending') {
        throw new ConflictError('Pairing session already has a pending request', 'pairing_request_exists');
      }

      session.newDeviceId = newDeviceId;
      session.newDeviceName = newDeviceName || 'New device';
      session.newDevicePublicIdentityKeyX25519 = newDevicePublicIdentityKeyX25519;
      session.newDevicePublicIdentityKeyEd25519 = newDevicePublicIdentityKeyEd25519;
      session.newDeviceSignedPreKey = newDeviceSignedPreKey;
      session.newDeviceSignedPreKeySignature = newDeviceSignedPreKeySignature;
      const metadata = metadataSet({ platform, userAgent, locale, timezone }, requestMetadata);
      if (metadata.platform) session.newDevicePlatform = metadata.platform;
      if (metadata.userAgent) session.newDeviceUserAgent = metadata.userAgent;
      if (metadata.ipAddress) session.newDeviceIpAddress = metadata.ipAddress;
      if (metadata.ipLocation) session.newDeviceIpLocation = metadata.ipLocation;
      if (metadata.locale) session.newDeviceLocale = metadata.locale;
      if (metadata.timezone) session.newDeviceTimezone = metadata.timezone;
      session.challengeResponse = challengeResponse || null;
      session.status = 'awaiting_approval';
      await session.save();

      return { status: session.status, sessionId };
    },

    async approve({ sessionId, deviceAuthorizationSignature, approverUserId }) {
      const session = await PairingSession.findOne({ sessionId });
      ensureActive(session);

      if (session.parentUserId !== approverUserId) {
        throw new ForbiddenError('Not authorized to approve this pairing session', 'pairing_forbidden');
      }
      if (session.status !== 'awaiting_approval') {
        throw new ConflictError('Session is not awaiting approval', 'pairing_wrong_status');
      }

      const user = await User.findOne({ id: approverUserId }).lean();
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      let device = await Device.findOne({ deviceId: session.newDeviceId });
      if (device && device.parentUserId !== approverUserId) {
        throw new ConflictError('Device is already linked to another account', 'device_already_linked');
      }

      if (!device) {
        const deviceUserId = await nextDeviceUserId(user.username);
        try {
          device = await Device.create({
            deviceId: session.newDeviceId,
            parentUserId: approverUserId,
            deviceUserId,
            deviceName: session.newDeviceName,
            platform: session.newDevicePlatform,
            userAgent: session.newDeviceUserAgent,
            ipAddress: session.newDeviceIpAddress,
            ipLocation: session.newDeviceIpLocation,
            locale: session.newDeviceLocale,
            timezone: session.newDeviceTimezone,
            isPrimary: false,
            isRevoked: false,
            publicIdentityKeyX25519: session.newDevicePublicIdentityKeyX25519,
            publicIdentityKeyEd25519: session.newDevicePublicIdentityKeyEd25519,
            signedPreKey: session.newDeviceSignedPreKey,
            signedPreKeySignature: session.newDeviceSignedPreKeySignature,
            deviceAuthorizationSignature: deviceAuthorizationSignature || null,
            provisionedVia: 'pairing',
            lastSeen: new Date(),
          });
        } catch (err) {
          if (err?.code === 11000) {
            throw new ConflictError('Device is already linked. Generate a new QR and try again.', 'device_already_linked');
          }
          throw err;
        }
      } else {
        device.isRevoked = false;
        device.deviceName = session.newDeviceName || device.deviceName;
        if (session.newDevicePlatform) device.platform = session.newDevicePlatform;
        if (session.newDeviceUserAgent) device.userAgent = session.newDeviceUserAgent;
        if (session.newDeviceIpAddress) device.ipAddress = session.newDeviceIpAddress;
        if (session.newDeviceIpLocation) device.ipLocation = session.newDeviceIpLocation;
        if (session.newDeviceLocale) device.locale = session.newDeviceLocale;
        if (session.newDeviceTimezone) device.timezone = session.newDeviceTimezone;
        device.publicIdentityKeyX25519 = session.newDevicePublicIdentityKeyX25519;
        device.publicIdentityKeyEd25519 = session.newDevicePublicIdentityKeyEd25519;
        device.signedPreKey = session.newDeviceSignedPreKey;
        device.signedPreKeySignature = session.newDeviceSignedPreKeySignature;
        device.deviceAuthorizationSignature = deviceAuthorizationSignature || null;
        device.provisionedVia = 'pairing';
        device.lastSeen = new Date();
        await device.save();
      }

      const token = authService.issueDeviceJwt({
        userId: approverUserId,
        username: user.username,
        deviceId: session.newDeviceId,
        deviceUserId: device.deviceUserId,
      });

      session.deviceAuthorizationSignature = deviceAuthorizationSignature || null;
      session.status = 'approved';
      session.approvedDeviceUserId = device.deviceUserId;
      session.approvedToken = token;
      await session.save();

      return { status: 'approved', deviceId: session.newDeviceId, deviceUserId: device.deviceUserId, token, userId: approverUserId, username: user.username };
    },

    async reject({ sessionId, approverUserId }) {
      const session = await PairingSession.findOne({ sessionId });
      ensureActive(session);
      if (session.parentUserId !== approverUserId) {
        throw new ForbiddenError('Not authorized', 'pairing_forbidden');
      }
      session.status = 'rejected';
      await session.save();
      return { status: 'rejected' };
    },

    // Called by new device polling after submitRequest — returns token when approved
    async pollResult({ sessionId }) {
      const s = await PairingSession.findOne({ sessionId }).lean();
      if (!s) throw new NotFoundError('Pairing session not found', 'pairing_not_found');
      if (s.status === 'approved') {
        return {
          status: 'approved',
          token: s.approvedToken,
          deviceId: s.newDeviceId,
          deviceUserId: s.approvedDeviceUserId,
          userId: s.parentUserId,
        };
      }
      return { status: s.status };
    },
  };
}

module.exports = { createPairingService };
