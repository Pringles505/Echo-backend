const crypto = require('node:crypto');
const { customAlphabet } = require('nanoid');
const {
  BadRequestError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
} = require('../../../shared/errors');

const DEFAULT_TTL_MS = 90_000;
const MAX_TTL_MS = 120_000;
const MAX_CHUNK_SIZE = 256 * 1024;
const MAX_CHUNK_COUNT = 256;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;

function sha256(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function publicView(doc) {
  return {
    sessionId: doc.sessionId,
    status: doc.status,
    sessionCode: doc.sessionCode,
    expiresAt: doc.expiresAt,
    createdAt: doc.createdAt,
    approvedAt: doc.approvedAt,
    completedAt: doc.completedAt,
    sourceUserId: doc.sourceUserId,
    sourceUsername: doc.sourceUsername,
    sourceEphemeralPubKey: doc.sourceEphemeralPubKey,
    targetEphemeralPubKey: doc.targetEphemeralPubKey,
    sourceConfirmed: Boolean(doc.sourceConfirmed),
    targetConfirmed: Boolean(doc.targetConfirmed),
    totalChunkCount: doc.totalChunkCount || 0,
    receivedChunkCount: Array.isArray(doc.chunks) ? doc.chunks.length : 0,
    totalPayloadBytes: doc.totalPayloadBytes || 0,
    sourceDevice: doc.sourceDevice || null,
    targetDevice: doc.targetDevice || null,
    targetDeviceIdentityPubX25519: doc.targetDeviceIdentityPubX25519 || null,
    targetDeviceIdentityPubEd25519: doc.targetDeviceIdentityPubEd25519 || null,
    deviceAuthorizationSignature: doc.deviceAuthorizationSignature || null,
  };
}

function createDeviceSyncService({ DeviceSyncSession, User, Device = null, authService, limits = {} }) {
  const ttlMs = Math.min(Math.max(limits.ttlMs || DEFAULT_TTL_MS, 10_000), MAX_TTL_MS);
  const maxChunkSize = limits.maxChunkSize || MAX_CHUNK_SIZE;
  const maxChunkCount = limits.maxChunkCount || MAX_CHUNK_COUNT;
  const maxTotalBytes = limits.maxTotalBytes || MAX_TOTAL_BYTES;
  const nanoid = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 8);
  const codegen = customAlphabet('0123456789', 6);

  function ensureNotExpired(session) {
    if (!session) {
      throw new NotFoundError('Sync session not found', 'sync_session_not_found');
    }
    // Check terminal statuses before TTL so completed stays completed.
    if (session.status === 'completed') {
      throw new ConflictError('Sync session already completed', 'sync_session_completed');
    }
    if (session.status === 'cancelled') {
      throw new ConflictError('Sync session is no longer active', 'sync_session_inactive');
    }
    if (session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now()) {
      session.status = 'expired';
      throw new ConflictError('Sync session expired', 'sync_session_expired');
    }
    if (session.status === 'expired') {
      throw new ConflictError('Sync session is no longer active', 'sync_session_inactive');
    }
  }

  async function loadSessionById(sessionId) {
    return DeviceSyncSession.findOne({ sessionId });
  }

  async function requireTargetSession(sessionId, targetAccessToken) {
    if (!targetAccessToken) {
      throw new ForbiddenError('Missing target session token', 'missing_target_sync_token');
    }
    const session = await loadSessionById(sessionId);
    ensureNotExpired(session);
    if (session.targetAccessTokenHash !== sha256(targetAccessToken)) {
      throw new ForbiddenError('Invalid target session token', 'invalid_target_sync_token');
    }
    return session;
  }

  return {
    limits: { ttlMs, maxChunkSize, maxChunkCount, maxTotalBytes },

    async createSession({ targetEphemeralPubKey, sessionCode, origin = null, version = null, targetDevice = {}, sourceUserId = null }) {
      if (!targetEphemeralPubKey) {
        throw new BadRequestError('Missing targetEphemeralPubKey', 'missing_target_ephemeral_key');
      }

      const sessionId = nanoid();
      const targetAccessToken = randomToken();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlMs);
      const doc = await DeviceSyncSession.create({
        sessionId,
        targetEphemeralPubKey,
        sessionCode: sessionCode || codegen(),
        targetAccessTokenHash: sha256(targetAccessToken),
        status: 'pending_source',
        expiresAt,
        origin,
        version,
        targetDevice,
        ...(sourceUserId ? { sourceUserId } : {}),
      });

      return {
        sessionId,
        sessionCode: doc.sessionCode,
        expiresAt: doc.expiresAt,
        targetAccessToken,
        status: doc.status,
      };
    },

    async getSessionForTarget({ sessionId, targetAccessToken }) {
      const session = await requireTargetSession(sessionId, targetAccessToken);
      return publicView(session);
    },

    async submitSourceIdentity({ sessionId, targetAccessToken, sourceIdentityPubKey, sourceDevice = {} }) {
      if (!sourceIdentityPubKey) {
        throw new BadRequestError('Missing sourceIdentityPubKey', 'missing_source_identity_key');
      }
      const session = await requireTargetSession(sessionId, targetAccessToken);
      session.sourceEphemeralPubKey = sourceIdentityPubKey;
      session.sourceDevice = sourceDevice;
      session.status = 'awaiting_confirmation';
      session.approvedAt = new Date();
      await session.save();
      return publicView(session);
    },

    async getDhSession({ sessionId, targetAccessToken }) {
      const session = await requireTargetSession(sessionId, targetAccessToken);
      return publicView(session);
    },

    async getSessionForSource({ sessionId, userId }) {
      const session = await loadSessionById(sessionId);
      ensureNotExpired(session);
      if (session.sourceUserId && session.sourceUserId !== userId) {
        throw new ForbiddenError('Sync session belongs to a different source user', 'sync_session_forbidden');
      }
      return publicView(session);
    },

    async attachSource({ sessionId, sourceEphemeralPubKey, sourceUserId, sourceDevice = {} }) {
      if (!sourceEphemeralPubKey) {
        throw new BadRequestError('Missing sourceEphemeralPubKey', 'missing_source_ephemeral_key');
      }

      const session = await loadSessionById(sessionId);
      ensureNotExpired(session);

      if (session.sourceUserId && session.sourceUserId !== sourceUserId) {
        throw new ConflictError('Sync session already attached to another source user', 'sync_session_already_attached');
      }

      const user = await User.findOne({ id: sourceUserId }).lean();
      if (!user) {
        throw new NotFoundError('Source user not found', 'source_user_not_found');
      }

      session.sourceEphemeralPubKey = sourceEphemeralPubKey;
      session.sourceUserId = sourceUserId;
      session.sourceUsername = user.username;
      session.approvedAt = new Date();
      session.status = 'awaiting_confirmation';
      session.sourceDevice = sourceDevice;
      await session.save();

      return publicView(session);
    },

    async confirmSession({ sessionId, actor, userId = null, targetAccessToken = null, targetDevice = {} }) {
      const session = actor === 'target'
        ? await requireTargetSession(sessionId, targetAccessToken)
        : await loadSessionById(sessionId);

      ensureNotExpired(session);

      if (actor === 'source') {
        if (!userId || session.sourceUserId !== userId) {
          throw new ForbiddenError('Source confirmation requires the bound user', 'sync_session_forbidden');
        }
        session.sourceConfirmed = true;
      } else if (actor === 'target') {
        session.targetConfirmed = true;
        session.targetDevice = { ...session.targetDevice, ...targetDevice };
      } else {
        throw new BadRequestError('Unknown confirmation actor', 'invalid_sync_actor');
      }

      session.status = session.sourceConfirmed && session.targetConfirmed
        ? 'transferring'
        : 'awaiting_confirmation';
      await session.save();
      return publicView(session);
    },

    async transferChunk({ sessionId, userId, chunk }) {
      const session = await loadSessionById(sessionId);
      ensureNotExpired(session);

      if (session.sourceUserId !== userId) {
        throw new ForbiddenError('Only the bound source user may upload chunks', 'sync_session_forbidden');
      }
      if (!(session.sourceConfirmed && session.targetConfirmed)) {
        throw new ConflictError('Sync session is not ready for transfer', 'sync_session_not_confirmed');
      }

      const {
        index,
        totalCount,
        ciphertext,
        nonce = null,
        digest,
      } = chunk || {};

      if (!Number.isInteger(index) || index < 0) {
        throw new BadRequestError('Chunk index must be a non-negative integer', 'invalid_chunk_index');
      }
      if (!Number.isInteger(totalCount) || totalCount <= 0 || totalCount > maxChunkCount) {
        throw new BadRequestError('Chunk totalCount is invalid', 'invalid_chunk_total_count');
      }
      if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
        throw new BadRequestError('Chunk ciphertext is required', 'missing_chunk_ciphertext');
      }
      if (typeof digest !== 'string' || digest.length === 0) {
        throw new BadRequestError('Chunk digest is required', 'missing_chunk_digest');
      }

      const size = Buffer.byteLength(ciphertext, 'utf8') + Buffer.byteLength(digest, 'utf8') + Buffer.byteLength(nonce || '', 'utf8');
      if (size > maxChunkSize) {
        throw new RateLimitError('Chunk exceeds size limit', 'sync_chunk_too_large', { maxChunkSize });
      }

      const exists = (session.chunks || []).some((existing) => existing.index === index);
      if (exists) {
        throw new ConflictError('Chunk has already been uploaded', 'sync_chunk_replay');
      }

      const nextTotal = (session.totalPayloadBytes || 0) + size;
      if (nextTotal > maxTotalBytes) {
        throw new RateLimitError('Sync payload exceeds maximum size', 'sync_payload_too_large', { maxTotalBytes });
      }

      session.status = 'transferring';
      session.totalChunkCount = totalCount;
      session.totalPayloadBytes = nextTotal;
      session.chunks.push({
        index,
        totalCount,
        ciphertext,
        nonce,
        digest,
        size,
      });
      session.chunks.sort((a, b) => a.index - b.index);
      await session.save();
      return publicView(session);
    },

    async transferDhChunk({ sessionId, targetAccessToken, chunk }) {
      const session = await requireTargetSession(sessionId, targetAccessToken);
      ensureNotExpired(session);

      if (!session.sourceEphemeralPubKey) {
        throw new ConflictError('Sync session is waiting for scanner identity', 'sync_session_missing_source_key');
      }

      const {
        index,
        totalCount,
        ciphertext,
        nonce = null,
        digest,
      } = chunk || {};

      if (!Number.isInteger(index) || index < 0) {
        throw new BadRequestError('Chunk index must be a non-negative integer', 'invalid_chunk_index');
      }
      if (!Number.isInteger(totalCount) || totalCount <= 0 || totalCount > maxChunkCount) {
        throw new BadRequestError('Chunk totalCount is invalid', 'invalid_chunk_total_count');
      }
      if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
        throw new BadRequestError('Chunk ciphertext is required', 'missing_chunk_ciphertext');
      }
      if (typeof digest !== 'string' || digest.length === 0) {
        throw new BadRequestError('Chunk digest is required', 'missing_chunk_digest');
      }

      const size = Buffer.byteLength(ciphertext, 'utf8') + Buffer.byteLength(digest, 'utf8') + Buffer.byteLength(nonce || '', 'utf8');
      if (size > maxChunkSize) {
        throw new RateLimitError('Chunk exceeds size limit', 'sync_chunk_too_large', { maxChunkSize });
      }

      const exists = (session.chunks || []).some((existing) => existing.index === index);
      if (exists) {
        throw new ConflictError('Chunk has already been uploaded', 'sync_chunk_replay');
      }

      const nextTotal = (session.totalPayloadBytes || 0) + size;
      if (nextTotal > maxTotalBytes) {
        throw new RateLimitError('Sync payload exceeds maximum size', 'sync_payload_too_large', { maxTotalBytes });
      }

      session.status = 'transferring';
      session.totalChunkCount = totalCount;
      session.totalPayloadBytes = nextTotal;
      session.chunks.push({
        index,
        totalCount,
        ciphertext,
        nonce,
        digest,
        size,
      });
      session.chunks.sort((a, b) => a.index - b.index);
      await session.save();
      return publicView(session);
    },

    async listChunksForTarget({ sessionId, targetAccessToken }) {
      const session = await requireTargetSession(sessionId, targetAccessToken);
      ensureNotExpired(session);
      return {
        session: publicView(session),
        chunks: (session.chunks || []).map((chunk) => ({
          index: chunk.index,
          totalCount: chunk.totalCount,
          ciphertext: chunk.ciphertext,
          nonce: chunk.nonce,
          digest: chunk.digest,
        })),
      };
    },

    async complete({ sessionId, actor, userId = null, targetAccessToken = null, targetDevice = {}, requestMetadata = {} }) {
      if (actor === 'source') {
        const session = await loadSessionById(sessionId);
        // Allow source completion even if target already completed.
        if (!session) throw new NotFoundError('Sync session not found', 'sync_session_not_found');
        if (session.status === 'cancelled' || session.status === 'expired') {
          throw new ConflictError('Sync session is no longer active', 'sync_session_inactive');
        }
        if (!userId || session.sourceUserId !== userId) {
          throw new ForbiddenError('Only the bound source user may complete the sync', 'sync_session_forbidden');
        }
        if (session.status !== 'completed') {
          session.completedAt = new Date();
          session.status = 'completed';
          await session.save();
        }
        return { session: publicView(session) };
      }

      if (actor !== 'target') {
        throw new BadRequestError('Unknown completion actor', 'invalid_sync_actor');
      }

      // Target completion: validate token without blocking on 'completed' status (source may have finished first).
      if (!targetAccessToken) {
        throw new ForbiddenError('Missing target session token', 'missing_target_sync_token');
      }
      const session = await loadSessionById(sessionId);
      if (!session) throw new NotFoundError('Sync session not found', 'sync_session_not_found');
      if (session.status === 'cancelled') {
        throw new ConflictError('Sync session was cancelled', 'sync_session_cancelled');
      }
      if (session.status === 'expired' || (session.expiresAt && new Date(session.expiresAt).getTime() <= Date.now() && session.status === 'pending_source')) {
        throw new ConflictError('Sync session expired', 'sync_session_expired');
      }
      if (session.targetAccessTokenHash !== sha256(targetAccessToken)) {
        throw new ForbiddenError('Invalid target session token', 'invalid_target_sync_token');
      }
      if (!session.sourceUserId) {
        throw new ConflictError('Sync session has no source user attached', 'sync_session_missing_source');
      }

      const user = await User.findOne({ id: session.sourceUserId }).lean();
      if (!user) {
        throw new NotFoundError('Source user not found', 'source_user_not_found');
      }

      const deviceId = targetDevice.deviceId || session.targetDevice?.deviceId || crypto.randomUUID();
      const platform = targetDevice.platform || session.targetDevice?.platform || null;
      const deviceName = targetDevice.deviceName || session.targetDevice?.deviceName || null;
      const deviceRecord = await authService.upsertDeviceRecord({
        userId: user.id,
        deviceId,
        deviceName,
        platform,
        userAgent: targetDevice.userAgent || null,
        locale: targetDevice.locale || null,
        timezone: targetDevice.timezone || null,
        requestMetadata,
        provisionedVia: 'device-sync',
        // QR sync completion is the primary user's explicit re-authorization,
        // so a previously revoked record for the same deviceId is brought back.
        allowReenable: true,
      });

      const resolvedDeviceId = deviceRecord?.deviceId || deviceId;

      // Copy the authorization signature to the Device record to avoid loss.
      if (Device && session.deviceAuthorizationSignature) {
        await Device.updateOne(
          { deviceId: resolvedDeviceId },
          { $set: { deviceAuthorizationSignature: session.deviceAuthorizationSignature } }
        );
      }

      session.targetDevice = { ...session.targetDevice, deviceId: resolvedDeviceId, platform, deviceName };
      session.completedAt = new Date();
      session.status = 'completed';
      await session.save();

      const authResult = await authService.issueDeviceJwt({
        userId: user.id,
        username: user.username,
        deviceId: resolvedDeviceId,
        deviceUserId: deviceRecord?.deviceUserId || null,
        platform,
      });

      return {
        session: publicView(session),
        auth: authResult,
        user: { userId: user.id, username: user.username },
      };
    },

    // Target uploads the device IK public keys. No private keys.
    async submitTargetDeviceIdentity({ sessionId, targetAccessToken, pubX25519, pubEd25519 }) {
      if (typeof pubX25519 !== 'string' || pubX25519.length === 0) {
        throw new BadRequestError('Missing targetDeviceIdentityPubX25519', 'missing_target_device_identity_x25519');
      }
      if (typeof pubEd25519 !== 'string' || pubEd25519.length === 0) {
        throw new BadRequestError('Missing targetDeviceIdentityPubEd25519', 'missing_target_device_identity_ed25519');
      }
      const session = await requireTargetSession(sessionId, targetAccessToken);
      // Do not allow a different IK to replace an existing one in the session.
      if (session.targetDeviceIdentityPubX25519 && session.targetDeviceIdentityPubX25519 !== pubX25519) {
        throw new ConflictError('Target device IK already set for this session', 'target_device_identity_locked');
      }
      session.targetDeviceIdentityPubX25519 = pubX25519;
      session.targetDeviceIdentityPubEd25519 = pubEd25519;
      await session.save();
      return publicView(session);
    },

    // Source uploads the signature over the target IK public key.
    async submitDeviceAuthorization({ sessionId, userId, deviceAuthorizationSignature }) {
      if (typeof deviceAuthorizationSignature !== 'string' || deviceAuthorizationSignature.length === 0) {
        throw new BadRequestError('Missing deviceAuthorizationSignature', 'missing_device_authorization_signature');
      }
      const session = await loadSessionById(sessionId);
      ensureNotExpired(session);
      if (!session.sourceUserId || session.sourceUserId !== userId) {
        throw new ForbiddenError('Only the bound source user may sign the device authorization', 'sync_session_forbidden');
      }
      if (!session.targetDeviceIdentityPubX25519) {
        throw new ConflictError('Target device identity has not been submitted yet', 'target_device_identity_missing');
      }
      session.deviceAuthorizationSignature = deviceAuthorizationSignature;
      await session.save();
      return publicView(session);
    },

    async cancel({ sessionId, userId = null, targetAccessToken = null }) {
      const session = targetAccessToken
        ? await requireTargetSession(sessionId, targetAccessToken)
        : await loadSessionById(sessionId);

      ensureNotExpired(session);

      if (userId && session.sourceUserId && session.sourceUserId !== userId) {
        throw new ForbiddenError('Sync session belongs to another source user', 'sync_session_forbidden');
      }

      session.status = 'cancelled';
      session.cancelledAt = new Date();
      await session.save();
      return publicView(session);
    },
  };
}

module.exports = { createDeviceSyncService };
