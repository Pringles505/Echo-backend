/**
 * Application service for Signal Protocol pre-key and OPK management.
 *
 * Wraps the same domain logic used by the Socket.IO `opk.handlers.js` so the
 * REST surface (`/keys/*`) and the legacy socket events stay behaviorally
 * aligned. The service is pure-ish: it depends on the User model, an OPK
 * policy bag, an OPK rate limiter (the in-memory state shared with the socket
 * layer when the same instance is provided), and an optional notifier for
 * "low OPK" replenishment broadcasts.
 *
 * @module modules/keys/application/keysService
 */

const {
  BadRequestError,
  NotFoundError,
  RateLimitError,
  UnauthorizedError,
} = require('../../../shared/errors');

/**
 * Build the keys application service.
 *
 * @param {object} deps
 * @param {import('mongoose').Model} deps.User - User mongoose model
 * @param {object} deps.opkPolicy - OPK policy helpers
 * @param {number} deps.opkPolicy.OPK_MAX_STORED
 * @param {number} deps.opkPolicy.OPK_UPLOAD_MAX
 * @param {function} deps.opkPolicy.normalizeOneTimePreKeysPayload
 * @param {function} deps.opkPolicy.dedupeIncomingOpks
 * @param {function} deps.opkPolicy.capToRemainingCapacity
 * @param {function} deps.opkPolicy.computeOpkReplenishNeeded
 * @param {function} deps.opkPolicy.estimateOpkCountAfterConsume
 * @param {object} deps.opkLimiter - Rate limiter service (from createOpkLimiterService)
 * @param {object} deps.opkLimiter.OPK_BUNDLE_LIMITS
 * @param {object} deps.opkLimiter.opkLimiterState
 * @param {function} deps.opkLimiter.fixedWindowTake
 * @param {function} deps.opkLimiter.logOpkRequest
 * @param {object} [deps.notifier] - Optional notifier (createSocketNotifier()) used to nudge
 *   targets to replenish OPKs when their store is below the low watermark.
 * @returns {object} Service exposing the 6 use cases consumed by the HTTP router.
 */
function createKeysService({ User, opkPolicy, opkLimiter, notifier } = {}) {
  if (!User) throw new Error('createKeysService requires User model');
  if (!opkPolicy) throw new Error('createKeysService requires opkPolicy');
  if (!opkLimiter) throw new Error('createKeysService requires opkLimiter');

  const {
    OPK_MAX_STORED,
    OPK_UPLOAD_MAX,
    normalizeOneTimePreKeysPayload,
    dedupeIncomingOpks,
    capToRemainingCapacity,
    computeOpkReplenishNeeded,
    estimateOpkCountAfterConsume,
  } = opkPolicy;

  const { OPK_BUNDLE_LIMITS, opkLimiterState, fixedWindowTake, logOpkRequest } = opkLimiter;

  /**
   * Best-effort replenishment broadcast. Mirrors socket handler behavior; any
   * failure is swallowed because audit logs aren't load-bearing for the user.
   *
   * @param {string} targetUserId
   * @param {number|null} currentCountOverride
   */
  async function requestOpkReplenishmentIfLow(targetUserId, currentCountOverride = null) {
    if (!notifier || typeof notifier.emitToUser !== 'function') return;
    if (!notifier.isUserOnline?.(targetUserId)) return;

    const currentCount =
      typeof currentCountOverride === 'number'
        ? currentCountOverride
        : (await User.findOne({ id: targetUserId }, { oneTimePreKeys: 1 }))?.oneTimePreKeys?.length ?? 0;

    const needed = computeOpkReplenishNeeded(currentCount);
    if (needed <= 0) return;

    notifier.emitToUser(targetUserId, 'replenishOPKs', { needed });
  }

  return {
    /**
     * Resolve the signed pre-key + signature for a target user.
     *
     * @param {object} input
     * @param {string} input.targetUserId
     * @returns {Promise<{ signedPreKey: string, signature: string, spkId: number }>}
     */
    async getSignedPreKey({ targetUserId } = {}) {
      const targetId = String(targetUserId ?? '');
      if (!targetId) throw new BadRequestError('Missing targetUserId', 'invalid_target');

      const user = await User.findOne({ id: targetId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      return {
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
      };
    },

    async getIdentityKeyX25519({ targetUserId } = {}) {
      const targetId = String(targetUserId ?? '');
      if (!targetId) throw new BadRequestError('Missing targetUserId', 'invalid_target');

      const user = await User.findOne({ id: targetId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      return { publicIdentityKeyX25519: user.publicIdentityKeyX25519 };
    },

    async getIdentityKeyEd25519({ targetUserId } = {}) {
      const targetId = String(targetUserId ?? '');
      if (!targetId) throw new BadRequestError('Missing targetUserId', 'invalid_target');

      const user = await User.findOne({ id: targetId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      return { publicIdentityKeyEd25519: user.publicIdentityKeyEd25519 };
    },

    /**
     * Fetch a complete pre-key bundle for the target user, atomically consuming
     * one OPK if available. Replicates the multi-bucket rate limiting and lease
     * reuse semantics of `getPreKeyBundle` in opk.handlers.js so HTTP and socket
     * traffic share the same governance.
     *
     * @param {object} input
     * @param {string} input.requesterId
     * @param {string} [input.requesterDeviceId]
     * @param {string} input.targetUserId
     * @param {string} [input.ip]
     * @param {string} [input.userAgent]
     * @returns {Promise<{ bundle: object }>}
     * @throws {UnauthorizedError|BadRequestError|RateLimitError|NotFoundError}
     */
    async getPreKeyBundle({ requesterId, requesterDeviceId, targetUserId, ip = '', userAgent = '' } = {}) {
      const reqId = String(requesterId ?? '');
      const targetId = String(targetUserId ?? '');
      // Sibling devices on one account share `requesterId` (the parent user id
      // baked into the JWT), so leasing the bundle under that key returns the
      // same OPK to every sibling within the lease window; after the first
      // sibling's responder consumes it, the rest fail with "OPK private key
      // not found". Scope the lease (and per-pair request bucket) to the
      // sender's device. Defensively fall back to the parent id when the
      // device id is absent so unauthenticated/legacy callers still hit *some*
      // bucket; the requester rate limiter remains account-level.
      const reqDeviceId = String(requesterDeviceId ?? requesterId ?? '');
      const pairKey = `${reqDeviceId}:${targetId}`;

      if (!reqId) {
        logOpkRequest({ requesterId: null, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'unauthorized' });
        throw new UnauthorizedError('Unauthorized', 'unauthorized');
      }
      if (!targetId) {
        logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'invalid_target' });
        throw new BadRequestError('Missing targetUserId', 'invalid_target');
      }

      const req1 = fixedWindowTake(
        opkLimiterState.reqByRequester,
        reqId,
        OPK_BUNDLE_LIMITS.requesterRequests.max,
        OPK_BUNDLE_LIMITS.requesterRequests.windowMs
      );
      if (!req1.allowed) {
        logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_requester_requests', retryAfterMs: req1.retryAfterMs });
        throw new RateLimitError('Rate limited', 'rate_limited', { retryAfterMs: req1.retryAfterMs });
      }

      const req2 = fixedWindowTake(
        opkLimiterState.reqByPair,
        pairKey,
        OPK_BUNDLE_LIMITS.pairRequests.max,
        OPK_BUNDLE_LIMITS.pairRequests.windowMs
      );
      if (!req2.allowed) {
        logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_pair_requests', retryAfterMs: req2.retryAfterMs });
        throw new RateLimitError('Rate limited', 'rate_limited', { retryAfterMs: req2.retryAfterMs });
      }

      const req3 = fixedWindowTake(
        opkLimiterState.reqByTarget,
        targetId,
        OPK_BUNDLE_LIMITS.targetRequests.max,
        OPK_BUNDLE_LIMITS.targetRequests.windowMs
      );
      if (!req3.allowed) {
        logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_target_requests', retryAfterMs: req3.retryAfterMs });
        throw new RateLimitError('Rate limited', 'rate_limited', { retryAfterMs: req3.retryAfterMs });
      }

      const lease = opkLimiterState.leaseByPair.get(pairKey);
      if (lease && lease.expiresAt > Date.now()) {
        logOpkRequest({
          requesterId: reqId,
          targetUserId: targetId,
          pairKey,
          ip,
          userAgent,
          outcome: 'lease_reuse',
          opkConsumed: Boolean(lease?.bundle?.opk),
          opkId: lease?.bundle?.opk?.opkId ?? null,
        });
        return { bundle: lease.bundle };
      }

      const targetHasOpk = await User.exists({ id: targetId, 'oneTimePreKeys.0': { $exists: true } });
      if (targetHasOpk) {
        const c1 = fixedWindowTake(
          opkLimiterState.consumeByRequester,
          reqId,
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
          logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'rate_limited_opk_consumption', retryAfterMs });
          throw new RateLimitError('OPK consumption rate limited', 'rate_limited', { retryAfterMs });
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
        logOpkRequest({ requesterId: reqId, targetUserId: targetId, pairKey, ip, userAgent, outcome: 'target_not_found' });
        throw new NotFoundError('User not found', 'user_not_found');
      }

      const currentCount =
        typeof estimatedNewOpkCount === 'number'
          ? estimatedNewOpkCount
          : (user.oneTimePreKeys?.length ?? 0);
      requestOpkReplenishmentIfLow(targetId, currentCount).catch(() => {});

      const bundle = {
        publicIdentityKeyX25519: user.publicIdentityKeyX25519,
        publicIdentityKeyEd25519: user.publicIdentityKeyEd25519,
        signedPreKey: user.signedPreKey,
        signature: user.signature,
        spkId: user.signedPreKeyId ?? 0,
        opk: consumedOpk
          ? { opkId: consumedOpk.opkId, opkPub: consumedOpk.opkPub ?? consumedOpk.publicKey }
          : null,
      };

      opkLimiterState.leaseByPair.set(pairKey, {
        expiresAt: Date.now() + OPK_BUNDLE_LIMITS.pairLeaseMs,
        bundle,
      });
      logOpkRequest({
        requesterId: reqId,
        targetUserId: targetId,
        pairKey,
        ip,
        userAgent,
        outcome: 'success',
        opkConsumed: Boolean(bundle.opk),
        opkId: bundle.opk?.opkId ?? null,
      });

      return { bundle };
    },

    /**
     * Append OPKs uploaded by the authenticated user, capped to remaining
     * storage capacity and deduplicated against existing entries.
     *
     * @param {object} input
     * @param {string} input.userId
     * @param {Array} input.oneTimePreKeys
     * @returns {Promise<{ stored: number }>}
     */
    async uploadOneTimePreKeys({ userId, oneTimePreKeys } = {}) {
      const authedUserId = String(userId ?? '');
      if (!authedUserId) throw new UnauthorizedError('Unauthorized', 'unauthorized');

      const bounded = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_UPLOAD_MAX);
      if (bounded.length === 0) {
        throw new BadRequestError('No OPKs provided', 'no_opks_provided');
      }

      const user = await User.findOne({ id: authedUserId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      const existingOpks = user.oneTimePreKeys ?? [];
      const unique = dedupeIncomingOpks(existingOpks, bounded);
      const capped = capToRemainingCapacity(existingOpks.length, unique, OPK_MAX_STORED);

      if (capped.length > 0) {
        await User.updateOne(
          { id: authedUserId },
          { $push: { oneTimePreKeys: { $each: capped } } }
        );
      }

      return { stored: capped.length };
    },

    /**
     * Inspect the OPK pool for the authenticated user and report whether it
     * needs replenishment.
     *
     * @param {object} input
     * @param {string} input.userId
     * @returns {Promise<{ currentCount: number, needed: number }>}
     */
    async getOpkStatus({ userId } = {}) {
      const authedUserId = String(userId ?? '');
      if (!authedUserId) throw new UnauthorizedError('Unauthorized', 'unauthorized');

      const user = await User.findOne({ id: authedUserId }, { oneTimePreKeys: 1 });
      const currentCount = user?.oneTimePreKeys?.length ?? 0;
      const needed = computeOpkReplenishNeeded(currentCount);
      return { currentCount, needed };
    },
  };
}

module.exports = { createKeysService };
