const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * Builds an HTTP middleware that verifies a JWT bearer token using the
 * provided `jwt` module and signing secret. Mirrors the Socket.IO auth
 * flow: extracts and trims `Authorization: Bearer <token>`, verifies it,
 * and attaches the decoded payload to `req.user`.
 *
 * @param {object} deps
 * @param {*} deps.jwt - jsonwebtoken module
 * @param {string} [deps.secretEnv='JWT_SECRET'] - env var name to read secret from
 * @returns {{ requireAuth: import('express').RequestHandler, optionalAuth: import('express').RequestHandler }}
 */
function createAuthMiddleware({ jwt, secretEnv = 'JWT_SECRET' } = {}) {
  if (!jwt || typeof jwt.verify !== 'function') {
    throw new Error('createAuthMiddleware requires a jwt module with verify()');
  }

  function extractToken(req) {
    const header = req.headers?.authorization || req.headers?.Authorization;
    if (typeof header !== 'string') return null;
    const trimmed = header.trim();
    if (!trimmed.toLowerCase().startsWith('bearer ')) return null;
    const token = trimmed.slice(7).trim();
    return token.length > 0 ? token : null;
  }

  function unauthorized(res, message = 'Unauthorized') {
    return sendHttpError(res, 401, message, 'unauthorized');
  }

  const requireAuth = (req, res, next) => {
    const token = extractToken(req);
    if (!token) return unauthorized(res, 'Missing bearer token');

    const secret = process.env[secretEnv];
    if (!secret) return unauthorized(res, 'Server signing secret unavailable');

    jwt.verify(token, secret, (err, decoded) => {
      if (err || !decoded?.id) return unauthorized(res, 'Invalid or expired token');
      req.user = decoded;
      return next();
    });
  };

  const optionalAuth = (req, _res, next) => {
    const token = extractToken(req);
    if (!token) {
      req.user = null;
      return next();
    }
    const secret = process.env[secretEnv];
    if (!secret) {
      req.user = null;
      return next();
    }
    jwt.verify(token, secret, (err, decoded) => {
      req.user = err || !decoded?.id ? null : decoded;
      return next();
    });
  };

  return { requireAuth, optionalAuth };
}

module.exports = { createAuthMiddleware };
