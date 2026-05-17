const { v4: uuidv4 } = require('uuid');
const {
  BadRequestError,
  ForbiddenError,
  NotFoundError,
} = require('../../../shared/errors');

function cleanString(value, maxLength = 512) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

function normalizeIp(ip) {
  const value = cleanString(ip, 128);
  if (!value) return null;
  return value.replace(/^::ffff:/, '');
}

function isPrivateIp(ip) {
  if (!ip) return false;
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80:')
  );
}

function ipLocationLabel(ip) {
  if (!ip) return null;
  if (ip === '127.0.0.1' || ip === '::1') return 'Localhost';
  if (isPrivateIp(ip)) return 'Private network';
  return 'Public IP';
}

function normalizeDeviceMetadata(input = {}, requestMetadata = {}) {
  const ipAddress = normalizeIp(requestMetadata.ipAddress || input.ipAddress);
  return {
    deviceName: cleanString(input.deviceName, 120),
    platform: cleanString(input.platform, 80),
    userAgent: cleanString(requestMetadata.userAgent || input.userAgent, 512),
    ipAddress,
    ipLocation: cleanString(input.ipLocation, 120) || ipLocationLabel(ipAddress),
    locale: cleanString(input.locale, 40),
    timezone: cleanString(input.timezone, 80),
  };
}

function metadataSet(input = {}, requestMetadata = {}) {
  const metadata = normalizeDeviceMetadata(input, requestMetadata);
  return Object.fromEntries(Object.entries(metadata).filter(([, value]) => value != null));
}

function createDeviceManagementService({ Device, MessageEnvelope, User, authService = null }) {
  return {
    // List all active (non-revoked) devices for a user, returning public bundles
    async listDevices({ parentUserId }) {
      const devices = await Device.find({ parentUserId, isRevoked: false }).lean();
      return devices.map((d) => ({
        deviceId: d.deviceId,
        deviceUserId: d.deviceUserId,
        deviceName: d.deviceName,
        platform: d.platform,
        userAgent: d.userAgent,
        ipAddress: d.ipAddress,
        ipLocation: d.ipLocation,
        locale: d.locale,
        timezone: d.timezone,
        isPrimary: d.isPrimary,
        isRevoked: d.isRevoked,
        publicIdentityKeyX25519: d.publicIdentityKeyX25519,
        publicIdentityKeyEd25519: d.publicIdentityKeyEd25519,
        signedPreKey: d.signedPreKey,
        signedPreKeySignature: d.signedPreKeySignature,
        signedPreKeyId: d.signedPreKeyId,
        deviceAuthorizationSignature: d.deviceAuthorizationSignature,
        createdAt: d.createdAt,
        lastSeen: d.lastSeen,
      }));
    },

    // Return public key bundles for fanout — one OPK consumed per device (best effort)
    async getDeviceBundles({ parentUserId }) {
      const devices = await Device.find({ parentUserId, isRevoked: false }).lean();
      const bundles = [];
      for (const d of devices) {
        const opk = d.oneTimePreKeys && d.oneTimePreKeys.length > 0
          ? d.oneTimePreKeys[0]
          : null;

        if (opk) {
          // Atomically remove consumed OPK
          await Device.updateOne(
            { deviceId: d.deviceId },
            { $pull: { oneTimePreKeys: { opkId: opk.opkId } } }
          );
        }

        bundles.push({
          deviceId: d.deviceId,
          deviceUserId: d.deviceUserId,
          isPrimary: d.isPrimary,
          publicIdentityKeyX25519: d.publicIdentityKeyX25519,
          publicIdentityKeyEd25519: d.publicIdentityKeyEd25519,
          signedPreKey: d.signedPreKey,
          signedPreKeySignature: d.signedPreKeySignature,
          signedPreKeyId: d.signedPreKeyId,
          deviceAuthorizationSignature: d.deviceAuthorizationSignature,
          opk: opk || null,
        });
      }
      return bundles;
    },

    // Upload or replace a device's public key bundle after provisioning.
    // Creates the device record if it doesn't exist (echo-sync-v1 QR case).
    async registerDeviceKeys({ deviceId, requesterId, keyBundle, requestMetadata = {} }) {
      if (!deviceId || !requesterId) throw new BadRequestError('Missing deviceId or requesterId');
      if (!keyBundle || !keyBundle.publicIdentityKeyX25519) {
        throw new BadRequestError('keyBundle.publicIdentityKeyX25519 is required');
      }

      let device = await Device.findOne({ deviceId });

      if (!device) {
        // Device was never formally created (e.g. echo-sync-v1 QR case).
        // Create a minimal record and add it to the user's devices list.
        const user = await User.findOne({ id: requesterId }).lean();
        if (!user) throw new NotFoundError('User not found', 'user_not_found');

        const secondaryCount = await Device.countDocuments({
          parentUserId: requesterId,
          isPrimary: false,
          isRevoked: false,
        });
        const deviceUserId = `${user.username}_x${secondaryCount + 1}`;

        device = await Device.create({
          deviceId,
          parentUserId: requesterId,
          deviceUserId,
          deviceName: keyBundle.deviceName || 'Synced device',
          ...metadataSet(keyBundle, requestMetadata),
          isPrimary: false,
          isRevoked: false,
          provisionedVia: 'device-sync',
          lastSeen: new Date(),
        });

        await User.updateOne({ id: requesterId }, { $addToSet: { devices: deviceId } });
      } else if (device.parentUserId !== requesterId) {
        throw new ForbiddenError('Device does not belong to this user', 'device_forbidden');
      }

      const normalizedOpks = Array.isArray(keyBundle.oneTimePreKeys)
        ? keyBundle.oneTimePreKeys.map((o) => ({ opkId: String(o.opkId), opkPub: String(o.opkPub) }))
        : [];

      await Device.updateOne(
        { deviceId },
        {
          $set: {
            ...metadataSet(keyBundle, requestMetadata),
            publicIdentityKeyX25519: keyBundle.publicIdentityKeyX25519,
            publicIdentityKeyEd25519: keyBundle.publicIdentityKeyEd25519 || keyBundle.publicIdentityKeyX25519,
            signedPreKey: keyBundle.signedPreKey || keyBundle.publicIdentityKeyX25519,
            signedPreKeySignature: keyBundle.signedPreKeySignature || keyBundle.publicIdentityKeyX25519,
            signedPreKeyId: typeof keyBundle.signedPreKeyId === 'number' ? keyBundle.signedPreKeyId : 0,
            oneTimePreKeys: normalizedOpks,
            lastSeen: new Date(),
          },
        }
      );

      return { deviceId, deviceUserId: device.deviceUserId, registered: true };
    },

    async revokeDevice({ deviceId, requesterId }) {
      const device = await Device.findOne({ deviceId });
      if (!device) throw new NotFoundError('Device not found', 'device_not_found');
      if (device.parentUserId !== requesterId) {
        throw new ForbiddenError('Not authorized to revoke this device', 'device_revoke_forbidden');
      }

      device.isRevoked = true;
      await device.save();
      return { deviceId, revoked: true };
    },

    async touchLastSeen({ deviceId, metadata = {}, requestMetadata = {} }) {
      await Device.updateOne(
        { deviceId },
        { $set: { ...metadataSet(metadata, requestMetadata), lastSeen: new Date() } }
      );
    },

    // ── Envelopes ──────────────────────────────────────────────────────────────

    async storeEnvelopes({ envelopes, senderDeviceId, logicalSenderId }) {
      if (!Array.isArray(envelopes) || envelopes.length === 0) {
        throw new BadRequestError('envelopes must be a non-empty array');
      }
      const docs = envelopes.map((e) => ({
        envelopeId: uuidv4(),
        logicalSenderId,
        senderDeviceId,
        logicalRecipientId: e.logicalRecipientId,
        recipientDeviceId: e.recipientDeviceId,
        ciphertext: e.ciphertext,
        nonce: e.nonce,
        header: e.header || null,
        messageType: e.messageType || 'message',
        conversationId: e.conversationId,
      }));
      await MessageEnvelope.insertMany(docs);
      return { stored: docs.length };
    },

    async fetchEnvelopes({ deviceId, limit = 100 }) {
      const envelopes = await MessageEnvelope.find({
        recipientDeviceId: deviceId,
        deliveredAt: null,
      })
        .sort({ createdAt: 1 })
        .limit(limit)
        .lean();

      return envelopes.map((e) => ({
        envelopeId: e.envelopeId,
        logicalSenderId: e.logicalSenderId,
        senderDeviceId: e.senderDeviceId,
        conversationId: e.conversationId,
        ciphertext: e.ciphertext,
        nonce: e.nonce,
        header: e.header,
        messageType: e.messageType,
        createdAt: e.createdAt,
      }));
    },

    async ackEnvelope({ envelopeId, deviceId, status }) {
      const envelope = await MessageEnvelope.findOne({ envelopeId });
      if (!envelope) throw new NotFoundError('Envelope not found', 'envelope_not_found');
      if (envelope.recipientDeviceId !== deviceId) {
        throw new ForbiddenError('Not your envelope', 'envelope_forbidden');
      }
      const now = new Date();
      if (status === 'read') {
        envelope.readAt = now;
        envelope.deliveredAt = envelope.deliveredAt || now;
      } else {
        envelope.deliveredAt = now;
      }
      await envelope.save();
      return { envelopeId, status };
    },
  };
}

module.exports = { createDeviceManagementService };
