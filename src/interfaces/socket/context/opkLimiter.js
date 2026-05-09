/**
 * Socket context service for OPK (One-Time Pre-Key) request rate limiting.
 * @module interfaces/socket/context/opkLimiter
 */

const { OPK_BUNDLE_LIMITS } = require('../../../shared/constants');

/**
 * Creates OPK request limiting helpers for socket handlers.
 * Uses fixed-window rate limiting for various OPK operations.
 *
 * @param {import('mongoose').Model} OpkRequestLog - Mongoose model for logging OPK requests
 * @returns {object} OPK limiter service with rate limiting and logging utilities
 * @returns {object} .OPK_BUNDLE_LIMITS - Rate limit configuration
 * @returns {function} .fixedWindowTake - Check if operation is allowed under rate limit
 * @returns {function} .logOpkRequest - Log an OPK request attempt
 */
function createOpkLimiterService(OpkRequestLog) {
  const opkLimiterState = {
    reqByRequester: new Map(),
    reqByPair: new Map(),
    reqByTarget: new Map(),
    consumeByRequester: new Map(),
    consumeByTarget: new Map(),
    leaseByPair: new Map(),
  };

  /**
   * Fixed-window rate limiter implementation.
   * @param {Map<string,object>} map - State map for this rate limit bucket
   * @param {string} key - Identity key (user ID, pair ID, etc.)
   * @param {number} max - Maximum operations per window
   * @param {number} windowMs - Window duration in milliseconds
   * @param {number} [cost=1] - Operation cost (may consume multiple allowances)
   * @returns {object} { allowed: boolean, retryAfterMs: number }
   */
  function fixedWindowTake(map, key, max, windowMs, cost = 1) {
    const now = Date.now();
    const k = String(key ?? '');
    if (!k) return { allowed: false, retryAfterMs: windowMs };

    let state = map.get(k);
    if (!state || state.resetAt <= now) {
      state = { count: 0, resetAt: now + windowMs };
    }

    if (state.count + cost > max) {
      map.set(k, state);
      return { allowed: false, retryAfterMs: Math.max(0, state.resetAt - now) };
    }

    state.count += cost;
    map.set(k, state);
    return { allowed: true, retryAfterMs: 0 };
  }

  /**
   * Log an OPK request attempt to database for audit trail.
   * Failures are logged but don't block the operation.
   *
   * @param {object} entry - OPK request log entry
   * @param {string} entry.requesterId - User ID of requester
   * @param {string} entry.targetId - User ID of target/recipient
   * @param {string} entry.ipAddress - Client IP address
   * @param {string} entry.status - 'allowed' or 'blocked'
   * @param {string} [entry.reason] - Reason if blocked
   */
  function logOpkRequest(entry) {
    try {
      OpkRequestLog.create(entry).catch((err) => {
        console.warn('OPK request logging failed:', err?.message ?? err);
      });
    } catch (err) {
      console.warn('OPK request logging failed:', err?.message ?? err);
    }
  }

  return {
    OPK_BUNDLE_LIMITS,
    opkLimiterState,
    fixedWindowTake,
    logOpkRequest,
  };
}

/**
 * Extract client IP address from Socket.IO handshake.
 * Respects X-Forwarded-For header for proxied connections.
 *
 * @param {*} socket - Socket.IO socket instance
 * @returns {string} Client IP address or empty string if unavailable
 */
function getSocketIp(socket) {
  const raw = socket?.handshake?.headers?.['x-forwarded-for'];
  if (typeof raw === 'string' && raw.trim()) return raw.split(',')[0].trim();
  return String(socket?.handshake?.address ?? '');
}

module.exports = {
  createOpkLimiterService,
  getSocketIp,
  OPK_BUNDLE_LIMITS,
};
