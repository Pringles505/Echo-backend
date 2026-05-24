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

// When `requireAuth` ran earlier in the chain we scope the bucket to the user
// id; anonymous requests fall back to an IPv6-safe IP key.
function authAwareKey(req, res) {
  return req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req, res);
}

// Trust-proxy is disabled by default in Express; if running behind a proxy
// the host should configure `app.set('trust proxy', ...)` so these limiters
// see the real client IP.
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

// Search is scoped per-user when authenticated so active users on shared
// NATs don't trip each other's limits.
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Key bundle is scoped per-user. In E2E messaging each new conversation
// consumes one bundle, so this needs headroom for users with many contacts.
const keyBundleLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Refresh: the refresh token itself is the proof of identity, so this is
// keyed by IP — tight enough to limit refresh-token brute force.
const refreshLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Newsletter signup: anti-spam from anonymous IPs.
const newsletterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Contact / support form: anonymous submissions, same shape as newsletter.
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

// Event registration: keyed by authenticated user id to prevent a single
// user from spamming registrations across events.
const eventRegisterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Banner uploads carry 5-8 MB of base64 — keyed per user.
const bannerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authAwareKey,
  handler: standardJsonHandler,
});

// Status endpoint is cheap but shouldn't become a DoS amplifier.
const statusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
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
};
