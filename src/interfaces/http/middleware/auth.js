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
 * @param {*} [deps.User] - Mongoose User model. When provided, requireAdmin
 *   re-reads the role from the DB instead of trusting the JWT payload alone.
 * @returns {{ requireAuth: import('express').RequestHandler, optionalAuth: import('express').RequestHandler, requireAdmin: import('express').RequestHandler }}
 */
function createAuthMiddleware({ jwt, secretEnv = 'JWT_SECRET', User } = {}) {
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

  /**
   * Runs `requireAuth` and then asserts the authenticated user has the
   * `admin` role. When a `User` model is wired into deps, role is re-read
   * from the DB (defense in depth against stale JWTs). Otherwise it falls
   * back to `req.user.role` from the JWT payload.
   */
  const requireAdmin = (req, res, next) => {
    requireAuth(req, res, async (err) => {
      if (err) return next(err);
      try {
        let role = req.user?.role;
        if (User && typeof User.findOne === 'function') {
          const fresh = await User.findOne({ id: req.user.id }, { role: 1 }).lean();
          if (!fresh) {
            return sendHttpError(res, 401, 'User no longer exists', 'unauthorized');
          }
          role = fresh.role;
          req.user.role = role;
        }
        if (role !== 'admin') {
          return sendHttpError(
            res,
            403,
            'Admin privileges required',
            'forbidden_admin_required'
          );
        }
        return next();
      } catch (e) {
        return next(e);
      }
    });
  };

  return { requireAuth, optionalAuth, requireAdmin };
}

module.exports = { createAuthMiddleware };
