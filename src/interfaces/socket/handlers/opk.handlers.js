/**
 * Socket event handlers for Signal Protocol pre-keys and One-Time Pre-Keys (OPK).
 * Implements Signal Protocol key bundle distribution and OPK lifecycle management
 * with rate limiting to prevent abuse.
 * @module interfaces/socket/handlers/opk
 */

const { getSocketIp } = require('../context/opkLimiter');

/**
 * @typedef {object} SignedPreKeyResponse
 * @property {boolean} success
 * @property {string} [signedPreKey] - Base64-encoded signed pre-key
 * @property {string} [signature] - Base64-encoded signature
 * @property {number} [spkId] - Signed pre-key ID
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} IdentityKeyResponse
 * @property {boolean} success
 * @property {string} [publicIdentityKeyX25519] - X25519 public key
 * @property {string} [publicIdentityKeyEd25519] - Ed25519 public key
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} PreKeyBundleResponse
 * @property {boolean} success
 * @property {string} [signedPreKey] - Signed pre-key (base64)
 * @property {string} [signature] - SPK signature (base64)
 * @property {Array} [oneTimePreKeys] - Array of available OPKs
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} UploadOPKPayload
 * @property {Array} oneTimePreKeys - Array of OPK objects to upload
 */

/**
 * @typedef {object} OPKStatusResponse
 * @property {boolean} success
 * @property {number} [count] - Current OPK count
 * @property {string} [error] - Error message if failed
 */

/**
 * Registers Socket.IO handlers for Signal Protocol key operations.
 * Enforces rate limiting on key bundle requests to prevent exhaustion attacks.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
 * @param {import('mongoose').Model} deps.User - User model
 * @param {import('mongoose').Model} [deps.Device] - Device model (optional)
 * @param {function} deps.normalizeOneTimePreKeysPayload - OPK normalization function
 * @param {function} deps.dedupeIncomingOpks - Deduplication function for OPKs
 * @param {function} deps.capToRemainingCapacity - Cap OPKs to available space
 * @param {function} deps.computeOpkReplenishNeeded - Calculate OPKs needed
 * @param {function} deps.estimateOpkCountAfterConsume - Estimate OPK count post-consumption
 * @param {number} deps.OPK_MAX_STORED - Maximum OPKs per user
 * @param {number} deps.OPK_UPLOAD_MAX - Maximum OPKs per upload
 * @param {object} deps.opkLimiter - Rate limiter service
 */
function registerOpkSocketHandlers(deps) {
  const {
    socket,
    io,
    userSocketMap,
    User,
    Device,
    normalizeOneTimePreKeysPayload,
    dedupeIncomingOpks,
    capToRemainingCapacity,
    computeOpkReplenishNeeded,
    estimateOpkCountAfterConsume,
    OPK_MAX_STORED,
    OPK_UPLOAD_MAX,
    opkLimiter,
  } = deps;
  const { OPK_BUNDLE_LIMITS, opkLimiterState, fixedWindowTake, logOpkRequest } = opkLimiter;

  const requestOpkReplenishmentIfLow = async (targetUserId, currentCountOverride = null) => {
    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return;

    const currentCount =
      typeof currentCountOverride === 'number'
        ? currentCountOverride
        : (await User.findOne({ id: targetUserId }, { oneTimePreKeys: 1 }))?.oneTimePreKeys?.length ?? 0;

    const needed = computeOpkReplenishNeeded(currentCount);
    if (needed <= 0) return;

    io.to(targetSocketId).emit('replenishOPKs', { needed });
  };

  socket.on('getSignedPreKey', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching SignedPreKey for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) return callback({ success: false, error: 'User not found' });
      callback({
        success: true,
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
      });
    } catch (error) {
      console.error('❌ Error fetching SignedPreKey:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getPublicIdentityKeyX25519', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching PublicIdentityKeyX25519 for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) return callback({ success: false, error: 'User not found' });
      callback({ success: true, publicIdentityKeyX25519: user.publicIdentityKeyX25519 });
    } catch (error) {
      console.error('❌ Error fetching publicIdentityKeyX25519:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getPublicIdentityKeyEd25519', async ({ targetUserId }, callback) => {
    console.log(`🔍 Fetching publicIdentityKeyEd25519 for user: ${targetUserId}`);
    try {
      const user = await User.findOne({ id: targetUserId });
      if (!user) return callback({ success: false, error: 'User not found' });
      callback({ success: true, publicIdentityKeyEd25519: user.publicIdentityKeyEd25519 });
    } catch (error) {
      console.error('❌ Error fetching publicIdentityKeyEd25519:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getPreKeyBundle', async ({ targetUserId }, callback) => {
    const requesterId = socket.user?.id;
    // Lease + per-pair rate limit must be scoped to the requesting *device*,
    // not the parent account: sibling devices share `socket.user.id` (it's the
    // parent user id from the JWT), so a user-level pairKey would hand every
    // sibling the same cached bundle within the 60s lease window, including
    // the OPK that the first sibling already had the responder consume.
    const requesterDeviceId =
      socket.user?.deviceUserId || socket.user?.deviceId || socket.user?.id;
    const targetId = String(targetUserId ?? '');
    const ip = getSocketIp(socket);
    const userAgent = String(socket?.handshake?.headers?.['user-agent'] ?? '');
    const pairKey = `${requesterDeviceId ?? ''}:${targetId}`;

    if (!requesterId) {
      logOpkRequest({ requesterId: null, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'unauthorized' });
      return callback?.({ success: false, error: 'Unauthorized' });
    }
    if (!targetId) {
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'invalid_target' });
      return callback?.({ success: false, error: 'Missing targetUserId' });
    }

    const req1 = fixedWindowTake(
      opkLimiterState.reqByRequester,
      requesterId,
      OPK_BUNDLE_LIMITS.requesterRequests.max,
      OPK_BUNDLE_LIMITS.requesterRequests.windowMs
    );
    if (!req1.allowed) {
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_requester_requests', retryAfterMs: req1.retryAfterMs });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req1.retryAfterMs });
    }

    const req2 = fixedWindowTake(
      opkLimiterState.reqByPair,
      pairKey,
      OPK_BUNDLE_LIMITS.pairRequests.max,
      OPK_BUNDLE_LIMITS.pairRequests.windowMs
    );
    if (!req2.allowed) {
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_pair_requests', retryAfterMs: req2.retryAfterMs });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req2.retryAfterMs });
    }

    const req3 = fixedWindowTake(
      opkLimiterState.reqByTarget,
      targetId,
      OPK_BUNDLE_LIMITS.targetRequests.max,
      OPK_BUNDLE_LIMITS.targetRequests.windowMs
    );
    if (!req3.allowed) {
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_target_requests', retryAfterMs: req3.retryAfterMs });
      return callback?.({ success: false, error: 'Rate limited', retryAfterMs: req3.retryAfterMs });
    }

    const lease = opkLimiterState.leaseByPair.get(pairKey);
    if (lease && lease.expiresAt > Date.now()) {
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'lease_reuse',
        opkConsumed: Boolean(lease?.bundle?.opk),
        opkId: lease?.bundle?.opk?.opkId ?? null,
      });
      return callback?.({ success: true, bundle: lease.bundle });
    }

    try {
      const targetHasOpk = await User.exists({ id: targetId, 'oneTimePreKeys.0': { $exists: true } });
      if (targetHasOpk) {
        const c1 = fixedWindowTake(
          opkLimiterState.consumeByRequester,
          requesterId,
          OPK_BUNDLE_LIMITS.requesterConsumes.max,
          OPK_BUNDLE_LIMITS.requesterConsumes.windowMs
        );
        const c2 = fixedWindowTake(
          opkLimiterState.consumeByTarget,
          targetId,
          OPK_BUNDLE_LIMITS.targetConsumes.max,
          OPK_BUNDLE_LIMITS.targetConsumes.windowMs
        );
        if (!c1.allowed || !c2.allowed) {
          const retryAfterMs = Math.max(c1.retryAfterMs ?? 0, c2.retryAfterMs ?? 0);
          logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_opk_consumption', retryAfterMs });
          return callback?.({ success: false, error: 'OPK consumption rate limited', retryAfterMs });
        }
      }

      const userWithOpk = await User.findOneAndUpdate(
        { id: targetId, 'oneTimePreKeys.0': { $exists: true } },
        { $pop: { oneTimePreKeys: -1 } },
        { new: false }
      );

      let user = userWithOpk;
      let consumedOpk = null;
      let estimatedNewOpkCount = null;

      if (userWithOpk) {
        consumedOpk = userWithOpk.oneTimePreKeys?.[0] ?? null;
        estimatedNewOpkCount = estimateOpkCountAfterConsume(userWithOpk.oneTimePreKeys?.length ?? 0);
      } else {
        user = await User.findOne({ id: targetId });
      }

      if (!user) {
        logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'target_not_found' });
        return callback({ success: false, error: 'User not found' });
      }

      const currentCount =
        typeof estimatedNewOpkCount === 'number'
          ? estimatedNewOpkCount
          : (user.oneTimePreKeys?.length ?? 0);
      requestOpkReplenishmentIfLow(targetId, currentCount).catch(() => { });

      const bundle = {
        publicIdentityKeyX25519: user.publicIdentityKeyX25519,
        publicIdentityKeyEd25519: user.publicIdentityKeyEd25519,
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
        opk: consumedOpk ? { opkId: consumedOpk.opkId, opkPub: consumedOpk.opkPub ?? consumedOpk.publicKey } : null,
      };

      opkLimiterState.leaseByPair.set(pairKey, { expiresAt: Date.now() + OPK_BUNDLE_LIMITS.pairLeaseMs, bundle });
      logOpkRequest({
        requesterId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'success',
        opkConsumed: Boolean(bundle.opk),
        opkId: bundle.opk?.opkId ?? null,
      });

      callback({ success: true, bundle });
    } catch (error) {
      console.error('❌ Error fetching PreKeyBundle:', error);
      logOpkRequest({ requesterId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'error' });
      callback({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('uploadOneTimePreKeys', async ({ oneTimePreKeys }, callback) => {
    try {
      const authedUserId = socket.user?.id;
      if (!authedUserId) return callback?.({ success: false, error: 'Unauthorized' });

      const bounded = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_UPLOAD_MAX);
      if (bounded.length === 0) return callback?.({ success: false, error: 'No OPKs provided' });

      const user = await User.findOne({ id: authedUserId });
      if (!user) return callback?.({ success: false, error: 'User not found' });

      const existingOpks = user.oneTimePreKeys ?? [];
      const unique = dedupeIncomingOpks(existingOpks, bounded);
      const capped = capToRemainingCapacity(existingOpks.length, unique, OPK_MAX_STORED);

      if (capped.length > 0) {
        await User.updateOne(
          { id: authedUserId },
          { $push: { oneTimePreKeys: { $each: capped } } }
        );
      }

      callback?.({ success: true, stored: capped.length });
    } catch (error) {
      console.error('❌ Error uploading OPKs:', error);
      callback?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getOpkStatus', async (_, callback) => {
    try {
      const authedUserId = socket.user?.id;
      if (!authedUserId) return callback?.({ success: false, error: 'Unauthorized' });

      const user = await User.findOne({ id: authedUserId }, { oneTimePreKeys: 1 });
      const currentCount = user?.oneTimePreKeys?.length ?? 0;
      const needed = computeOpkReplenishNeeded(currentCount);
      callback?.({ success: true, currentCount, needed });
    } catch (error) {
      console.error('❌ Error fetching OPK status:', error);
      callback?.({ success: false, error: 'Internal server error' });
    }
  });

  /**
   * 'publishDeviceKeyBundle' event - Replace the authenticated user's public key material.
   * Called after replaceCurrentDeviceIdentity (post-sync/pairing) to push new ELD-generated
   * keys to the server so other devices can run a fresh X3DH against the updated bundle.
   * Replaces all OPKs because the old OPK private keys no longer exist in ELD.
   *
   * @event publishDeviceKeyBundle
   * @param {{ deviceId: string, deviceName: string, platform: string, keyBundle: object }} data
   * @param {function} callback - Ack: { success: boolean, error?: string }
   */
  socket.on('publishDeviceKeyBundle', async (data, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const authedUserId = socket.user?.id;
      if (!authedUserId) return ack({ success: false, error: 'Unauthorized' });

      const { deviceId, deviceName, platform, keyBundle } = data ?? {};
      if (!keyBundle || !deviceId) return ack({ success: false, error: 'Missing required fields' });

      const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;
      if (!Array.isArray(publicSignedPreKey) || publicSignedPreKey.length < 2) {
        return ack({ success: false, error: 'Invalid publicSignedPreKey' });
      }

      const [signedPreKey, signature] = publicSignedPreKey;
      const normalizedOpks = normalizeOneTimePreKeysPayload(oneTimePreKeys ?? [], OPK_MAX_STORED);

      await User.updateOne(
        { id: authedUserId },
        {
          $set: {
            publicIdentityKeyX25519,
            publicIdentityKeyEd25519,
            signedPreKey,
            signature,
            signedPreKeyId: 0,
            oneTimePreKeys: normalizedOpks,
          },
        }
      );

      if (Device) {
        await Device.updateOne(
          { deviceId, parentUserId: authedUserId },
          {
            $set: {
              publicIdentityKeyX25519,
              publicIdentityKeyEd25519,
              signedPreKey,
              signedPreKeySignature: signature,
              signedPreKeyId: 0,
              lastSeen: new Date(),
              ...(deviceName ? { deviceName } : {}),
              ...(platform ? { platform } : {}),
            },
          }
        );
      }

      console.log(`[publishDeviceKeyBundle] Keys updated for user ${authedUserId} device ${deviceId}`);
      ack({ success: true });
    } catch (err) {
      console.error('❌ Error in publishDeviceKeyBundle:', err);
      ack({ success: false, error: 'Internal server error' });
    }
  });
}

module.exports = { registerOpkSocketHandlers };
