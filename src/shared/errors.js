/**
 * Domain/HTTP error types.
 *
 * Application services throw these so the Express `errorHandler` middleware
 * can map them to consistent HTTP responses (`{ success: false, error, code }`).
 * `status` and `code` are surfaced as-is by the error middleware.
 */

class HttpServiceError extends Error {
  constructor(status, message, code, details) {
    super(message);
    this.name = this.constructor.name;
    this.status = status;
    this.code = code;
    if (typeof details !== 'undefined') this.details = details;
  }
}

class BadRequestError extends HttpServiceError {
  constructor(message = 'Bad request', code = 'bad_request', details) {
    super(400, message, code, details);
  }
}

class UnauthorizedError extends HttpServiceError {
  constructor(message = 'Unauthorized', code = 'unauthorized', details) {
    super(401, message, code, details);
  }
}

class ForbiddenError extends HttpServiceError {
  constructor(message = 'Forbidden', code = 'forbidden', details) {
    super(403, message, code, details);
  }
}

class NotFoundError extends HttpServiceError {
  constructor(message = 'Resource not found', code = 'not_found', details) {
    super(404, message, code, details);
  }
}

class ConflictError extends HttpServiceError {
  constructor(message = 'Conflict', code = 'conflict', details) {
    super(409, message, code, details);
  }
}

class RateLimitError extends HttpServiceError {
  constructor(message = 'Rate limited', code = 'rate_limited', details) {
    super(429, message, code, details);
  }
}

module.exports = {
  HttpServiceError,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitError,
};
