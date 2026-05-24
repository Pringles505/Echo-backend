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

function hasDeviceKeyBundle(device) {
  return Boolean(
    device?.publicIdentityKeyX25519 &&
    device?.publicIdentityKeyEd25519 &&
    device?.signedPreKey &&
    device?.signedPreKeySignature
  );
}

function isVisibleDevice(device) {
  return Boolean(device?.isPrimary || hasDeviceKeyBundle(device));
}

async function nextSecondaryDeviceUserId(Device, User, mainUserId) {
  const digits = () => Math.floor(10000000 + Math.random() * 90000000).toString();
  let candidate = `${mainUserId}_${digits()}`;
  while (await Device.exists({ deviceUserId: candidate }) || await User.exists({ id: candidate })) {
    candidate = `${mainUserId}_${digits()}`;
  }
  return candidate;
}

async function upsertDeviceUser({ User, parentUser, deviceUserId, keyBundle, opks }) {
  const publicSignedPreKey = keyBundle.signedPreKey || null;
  const signature = keyBundle.signedPreKeySignature || keyBundle.signature || null;
  if (!publicSignedPreKey || !signature || !keyBundle.publicIdentityKeyEd25519) return;
  const set = {
    id: deviceUserId,
    username: deviceUserId,
    hashedPassword: parentUser.hashedPassword || '',
    publicIdentityKeyX25519: keyBundle.publicIdentityKeyX25519,
    publicIdentityKeyEd25519: keyBundle.publicIdentityKeyEd25519,
    signedPreKey: publicSignedPreKey,
    signature,
    signedPreKeyId: keyBundle.signedPreKeyId ?? 0,
    aboutme: '',
    profilePicture: '',
  };
  if (Array.isArray(opks)) set.oneTimePreKeys = opks;

  await User.updateOne(
    { id: deviceUserId },
    {
      $set: set,
      $setOnInsert: {
        friends: [],
        devices: [],
      },
    },
    { upsert: true }
  );
}

function createDeviceManagementService({ Device, MessageEnvelope, User, io = null, authService = null }) {
  return {
    async listDevices({ parentUserId }) {
      const devices = await Device.find({ parentUserId, isRevoked: false }).lean();
      return devices.filter(isVisibleDevice).map((d) => ({
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
        isSynced: hasDeviceKeyBundle(d),
        createdAt: d.createdAt,
        lastSeen: d.lastSeen,
      }));
    },

    // Non-consuming lookup used by the X3DH responder: no OPK is consumed and
    // no signed-prekey rotation occurs. The sender already consumed an OPK to
    // construct the message, so calling getDeviceBundles here would burn
    // additional OPKs unnecessarily.
    async getDeviceIdentities({ parentUserId }) {
      const devices = await Device.find({ parentUserId, isRevoked: false }).lean();
      return devices.filter(hasDeviceKeyBundle).map((d) => ({
        deviceId: d.deviceId,
        deviceUserId: d.deviceUserId,
        isPrimary: d.isPrimary,
        publicIdentityKeyX25519: d.publicIdentityKeyX25519,
        publicIdentityKeyEd25519: d.publicIdentityKeyEd25519,
        signedPreKey: d.signedPreKey,
        signedPreKeySignature: d.signedPreKeySignature,
        signedPreKeyId: d.signedPreKeyId,
        deviceAuthorizationSignature: d.deviceAuthorizationSignature,
      }));
    },

    // One OPK consumed per device (best effort).
    async getDeviceBundles({ parentUserId }) {
      const devices = await Device.find({ parentUserId, isRevoked: false }).lean();
      const bundles = [];
      for (const d of devices.filter(hasDeviceKeyBundle)) {
        const opk = d.oneTimePreKeys && d.oneTimePreKeys.length > 0
          ? d.oneTimePreKeys[0]
          : null;

        if (opk) {
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

    // Creates the device record if it doesn't exist (echo-sync-v1 QR case).
    async registerDeviceKeys({ deviceId, requesterId, keyBundle, requestMetadata = {} }) {
      if (!deviceId || !requesterId) throw new BadRequestError('Missing deviceId or requesterId');
      if (!keyBundle || !keyBundle.publicIdentityKeyX25519) {
        throw new BadRequestError('keyBundle.publicIdentityKeyX25519 is required');
      }

      let device = await Device.findOne({ deviceId });

      if (!device) {
        const user = await User.findOne({ id: requesterId }).lean();
        if (!user) throw new NotFoundError('User not found', 'user_not_found');

        const deviceUserId = await nextSecondaryDeviceUserId(Device, User, user.id);

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

        await User.updateOne({ id: requesterId }, { $addToSet: { devices: deviceUserId } });
      } else if (device.parentUserId !== requesterId) {
        throw new ForbiddenError('Device does not belong to this user', 'device_forbidden');
      }

      const normalizedOpks = Array.isArray(keyBundle.oneTimePreKeys)
        ? keyBundle.oneTimePreKeys.map((o) => ({ opkId: String(o.opkId), opkPub: String(o.opkPub) }))
        : [];

      // Only persist deviceAuthorizationSignature when the bundle carries one
      // so re-uploads without it don't clobber an existing verified signature.
      const authSig =
        typeof keyBundle.deviceAuthorizationSignature === 'string'
          && keyBundle.deviceAuthorizationSignature.length > 0
            ? keyBundle.deviceAuthorizationSignature
            : null;

      // Only set a key-material field when the incoming payload actually carries
      // it; otherwise a metadata-only heartbeat would clobber a valid SPK signature.
      const update = {
        ...metadataSet(keyBundle, requestMetadata),
        publicIdentityKeyX25519: keyBundle.publicIdentityKeyX25519,
        lastSeen: new Date(),
      };
      if (typeof keyBundle.publicIdentityKeyEd25519 === 'string' && keyBundle.publicIdentityKeyEd25519.length > 0) {
        update.publicIdentityKeyEd25519 = keyBundle.publicIdentityKeyEd25519;
      }
      if (typeof keyBundle.signedPreKey === 'string' && keyBundle.signedPreKey.length > 0) {
        update.signedPreKey = keyBundle.signedPreKey;
      }
      if (typeof keyBundle.signedPreKeySignature === 'string' && keyBundle.signedPreKeySignature.length > 0) {
        update.signedPreKeySignature = keyBundle.signedPreKeySignature;
      }
      if (typeof keyBundle.signedPreKeyId === 'number') {
        update.signedPreKeyId = keyBundle.signedPreKeyId;
      }
      if (Array.isArray(keyBundle.oneTimePreKeys)) {
        update.oneTimePreKeys = normalizedOpks;
      }
      if (authSig) update.deviceAuthorizationSignature = authSig;

      await Device.updateOne({ deviceId }, { $set: update });
      const parentUser = await User.findOne({ id: requesterId }).lean();
      if (parentUser) {
        await upsertDeviceUser({
          User,
          parentUser,
          deviceUserId: device.deviceUserId,
          keyBundle,
          opks: normalizedOpks,
        });
        await User.updateOne({ id: requesterId }, { $addToSet: { devices: device.deviceUserId } });
      }

      return { deviceId, deviceUserId: device.deviceUserId, registered: true };
    },

    async revokeDevice({ deviceId, requesterId }) {
      const device = await Device.findOne({ deviceId });
      if (!device) throw new NotFoundError('Device not found', 'device_not_found');
      if (device.parentUserId !== requesterId) {
        throw new ForbiddenError('Not authorized to revoke this device', 'device_revoke_forbidden');
      }
      if (device.isPrimary) {
        throw new ForbiddenError(
          'The primary device cannot be revoked',
          'primary_device_revoke_forbidden'
        );
      }

      if (device.isRevoked) {
        return { deviceId, revoked: true };
      }

      device.isRevoked = true;
      await device.save();

      // Terminate any active socket bound to this deviceId (single-node deployment).
      if (io?.sockets?.sockets) {
        try {
          for (const [, socket] of io.sockets.sockets) {
            if (socket?.user?.deviceId === deviceId) {
              try {
                socket.emit('deviceRevoked', { deviceId, reason: 'revoked_by_owner' });
              } catch { /* emit best-effort */ }
              try {
                socket.disconnect(true);
              } catch { /* disconnect best-effort */ }
            }
          }
        } catch { /* iteration best-effort; HTTP/socket guards will still reject this device */ }
      }

      return { deviceId, revoked: true };
    },

    async touchLastSeen({ deviceId, metadata = {}, requestMetadata = {} }) {
      await Device.updateOne(
        { deviceId },
        { $set: { ...metadataSet(metadata, requestMetadata), lastSeen: new Date() } }
      );
    },

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
