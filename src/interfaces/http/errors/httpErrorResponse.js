function sendHttpError(res, status, error, code = null, details = undefined) {
  const payload = {
    success: false,
    error,
  };

  if (code) payload.code = code;
  if (typeof details !== 'undefined') payload.details = details;

  return res.status(status).json(payload);
}

module.exports = { sendHttpError };
