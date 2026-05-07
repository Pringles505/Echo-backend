const rateLimit = require('express-rate-limit');

const standardJsonHandler = (_req, res, _next, options) => {
  res.status(options.statusCode || 429).json({
    success: false,
    error: 'Too many requests, please try again later',
    code: 'rate_limited',
    retryAfterMs: options.windowMs,
  });
};

/**
 * Rate limiters tuned for auth-sensitive surfaces. Keyed by IP.
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

const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

const keyBundleLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  handler: standardJsonHandler,
});

module.exports = {
  loginLimiter,
  registerLimiter,
  searchLimiter,
  keyBundleLimiter,
};
