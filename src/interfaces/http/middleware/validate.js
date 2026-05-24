const { sendHttpError } = require('../errors/httpErrorResponse');

// Rule shape: { field, type?, required = true, custom? }
//   type:   'string' | 'number' | 'boolean' | 'array' | 'object'
//   custom: (value, body) => string | null   (error message if invalid)
// On the first failure, responds 400 with code `validation_error` and the
// offending field name in `details`.
function validateBody(rules) {
  return (req, res, next) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    for (const rule of rules) {
      const { field, type, required = true, custom } = rule;
      const value = body[field];

      if (value === undefined || value === null) {
        if (required) {
          return sendHttpError(
            res,
            400,
            `Missing required field: ${field}`,
            'validation_error',
            field
          );
        }
        continue;
      }

      if (type) {
        const ok = type === 'array' ? Array.isArray(value) : typeof value === type;
        if (!ok) {
          return sendHttpError(
            res,
            400,
            `Invalid type for field: ${field} (expected ${type})`,
            'validation_error',
            field
          );
        }
      }

      if (typeof custom === 'function') {
        const err = custom(value, body);
        if (typeof err === 'string') {
          return sendHttpError(res, 400, err, 'validation_error', field);
        }
      }
    }
    return next();
  };
}

function requireDatabase(mongoose) {
  return (_req, res, next) => {
    if (mongoose.connection.readyState === 1) return next();
    return sendHttpError(
      res,
      503,
      'Database connection is not available',
      'database_unavailable'
    );
  };
}

module.exports = { validateBody, requireDatabase };
