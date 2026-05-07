const test = require('node:test');
const assert = require('node:assert/strict');

const {
  notFoundHandler,
  errorHandler,
} = require('../src/interfaces/http/middleware/errorHandlers');

function createMockRes() {
  return {
    headersSent: false,
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

test('notFoundHandler returns structured 404 response', () => {
  const res = createMockRes();
  notFoundHandler({}, res);
  assert.equal(res.statusCode, 404);
  assert.deepEqual(res.body, {
    success: false,
    error: 'Route not found',
    code: 'not_found',
  });
});

test('errorHandler preserves explicit non-5xx status and code', () => {
  const previousEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';

  try {
    const res = createMockRes();
    const err = new Error('Conflict detected');
    err.status = 409;
    err.code = 'conflict';

    errorHandler(err, {}, res, () => {});

    assert.equal(res.statusCode, 409);
    assert.deepEqual(res.body, {
      success: false,
      error: 'Conflict detected',
      code: 'conflict',
      details: 'Conflict detected',
    });
  } finally {
    process.env.NODE_ENV = previousEnv;
  }
});

test('errorHandler hides details for 5xx errors in production', () => {
  const previousEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';

  try {
    const res = createMockRes();
    const err = new Error('Sensitive internal message');
    errorHandler(err, {}, res, () => {});

    assert.equal(res.statusCode, 500);
    assert.deepEqual(res.body, {
      success: false,
      error: 'Unexpected server error',
    });
  } finally {
    process.env.NODE_ENV = previousEnv;
  }
});
