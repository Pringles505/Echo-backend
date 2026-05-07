const { sendHttpError } = require('../errors/httpErrorResponse');

function notFoundHandler(req, res) {
  return sendHttpError(res, 404, 'Route not found', 'not_found');
}

function errorHandler(err, _req, res, _next) {
  if (res.headersSent) return;

  const status = Number.isInteger(err?.status) ? err.status : 500;
  const error = status >= 500
    ? 'Unexpected server error'
    : (err?.message || 'Request failed');
  const code = typeof err?.code === 'string' ? err.code : null;
  const details = process.env.NODE_ENV === 'production'
    ? undefined
    : (err?.message || undefined);

  console.error('Unhandled HTTP error:', err);
  return sendHttpError(res, status, error, code, details);
}

module.exports = { notFoundHandler, errorHandler };
