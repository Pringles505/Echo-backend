const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * Lightweight body validator. Each rule is `{ field, type?, required?, custom? }`.
 *
 *   type: 'string' | 'number' | 'boolean' | 'array' | 'object'
 *   required: boolean (default true)
 *   custom: (value, body) => string | null   -- returns error message if invalid
 *
 * On the first failure, responds with HTTP 400 and a `validation_error` code,
 * exposing the offending field via `details`.
 *
 * @param {Array<object>} rules
 * @returns {import('express').RequestHandler}
 */
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

/**
 * Asserts the database is connected before letting the request through.
 * @param {*} mongoose
 * @returns {import('express').RequestHandler}
 */
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
