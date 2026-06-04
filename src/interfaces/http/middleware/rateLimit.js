const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');

const standardJsonHandler = (_req, res, _next, options) => {
  res.status(options.statusCode || 429).json({
    success: false,
    error: 'Too many requests, please try again later',
    code: 'rate_limited',
    retryAfterMs: options.windowMs,
  });
};

/**
 * Auth-aware key: when an authenticated user is present (because `requireAuth`
 * ran earlier in the chain) the bucket is scoped to the user id. Anonymous
 * requests fall back to an IPv6-safe IP key.
 */
function authAwareKey(req, res) {
  return req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req, res);
}

/**
 * Rate limiters tuned for auth-sensitive surfaces. Keyed by IP by default.
 * Trust-proxy is disabled by default in Express; if running behind a proxy
 * the host should configure `app.set('trust proxy', ...)` so this works
 * with the actual client IP.
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Search: bumped from 30 → 60/min and scoped per-user when authenticated so
// active users on shared NATs don't trip each other's limits.
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Key bundle: bumped from 60 → 120/min and scoped per-user. In E2E messaging
// each new conversation consumes one bundle, so this needs headroom for
// users with many active contacts.
const keyBundleLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Refresh: the refresh token itself is the proof of identity, so this is
// keyed by IP. 30/min is plenty for normal token rotation and tight enough
// to limit refresh-token brute force.
const refreshLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Newsletter signup: aggressive anti-spam from anonymous IPs.
const newsletterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Contact / support form: same as newsletter — anonymous submissions.
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Event registration: keyed by authenticated user id to prevent a single
// user from spamming registrations across events. Falls back to a safe
// IPv6-aware IP key for requests that somehow slip past requireAuth.
const eventRegisterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Banner uploads are expensive (5-8 MB base64). Keyed per user.
const bannerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Status endpoint is cheap but should not become a DoS amplifier.
const statusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Encrypted media uploads are large (up to MEDIA_MAX_SIZE per blob). Keyed per
// authenticated user to bound disk/bandwidth abuse from a single account.
const mediaUploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

module.exports = {
  authAwareKey,
  loginLimiter,
  registerLimiter,
  searchLimiter,
  keyBundleLimiter,
  refreshLimiter,
  newsletterLimiter,
  contactLimiter,
  eventRegisterLimiter,
  bannerLimiter,
  statusLimiter,
  mediaUploadLimiter,
};
