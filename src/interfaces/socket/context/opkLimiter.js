const { OPK_BUNDLE_LIMITS } = require('../../../shared/constants');

function createOpkLimiterService(OpkRequestLog) {
  const opkLimiterState = {
    reqByRequester: new Map(),
    reqByPair: new Map(),
    reqByTarget: new Map(),
    consumeByRequester: new Map(),
    consumeByTarget: new Map(),
    leaseByPair: new Map(),
  };

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

  // Best-effort audit log: failures are swallowed so they never block the
  // OPK operation itself.
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

// Honours X-Forwarded-For so proxied connections aren't all collapsed onto
// the upstream proxy's address.
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
