const { sendHttpError } = require('../errors/httpErrorResponse');

function createAuthMiddleware({ jwt, User = null, Device = null, secretEnv = 'JWT_SECRET' } = {}) {
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

  function unauthorized(res, message = 'Unauthorized', code = 'unauthorized') {
    return sendHttpError(res, 401, message, code);
  }

  async function verifyDeviceBinding(decoded) {
    if (!Device || !decoded?.deviceId) return { ok: true };
    const device = await Device.findOne({ deviceId: decoded.deviceId }).lean();
    if (!device) return { ok: false, message: 'Device not registered', code: 'device_not_registered' };
    if (device.isRevoked) return { ok: false, message: 'Device has been revoked', code: 'device_revoked' };
    if (String(device.parentUserId) !== String(decoded.id)) {
      return { ok: false, message: 'Device does not belong to this user', code: 'device_forbidden' };
    }
    return { ok: true };
  }

  const requireAuth = (req, res, next) => {
    const token = extractToken(req);
    if (!token) return unauthorized(res, 'Missing bearer token');

    const secret = process.env[secretEnv];
    if (!secret) return unauthorized(res, 'Server signing secret unavailable');

    jwt.verify(token, secret, async (err, decoded) => {
      if (err || !decoded?.id) return unauthorized(res, 'Invalid or expired token');
      try {
        const check = await verifyDeviceBinding(decoded);
        if (!check.ok) return unauthorized(res, check.message, check.code);
      } catch {
        return unauthorized(res, 'Failed to verify device');
      }
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
    jwt.verify(token, secret, async (err, decoded) => {
      if (err || !decoded?.id) {
        req.user = null;
        return next();
      }
      try {
        const check = await verifyDeviceBinding(decoded);
        req.user = check.ok ? decoded : null;
      } catch {
        req.user = null;
      }
      return next();
    });
  };

  // When a User model is wired in we re-read the role from the DB so a stale
  // JWT can't keep admin privileges after the role was downgraded.
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
