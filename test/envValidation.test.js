const test = require('node:test');
const assert = require('node:assert/strict');

const {
  resolveMongoUriFromEnv,
  validateRuntimeEnv,
} = require('../src/config/loadEnv');

function withEnv(overrides, fn) {
  const keys = Object.keys(overrides);
  const previous = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined || value === null) delete process.env[key];
      else process.env[key] = value;
    }
    return fn();
  } finally {
    for (const key of keys) {
      const value = previous.get(key);
      if (typeof value === 'undefined') delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('resolveMongoUriFromEnv prefers MONGO_URI over MONGO_URI_SECRET', () => {
  withEnv(
    {
      MONGO_URI: '  mongodb://primary-uri  ',
      MONGO_URI_SECRET: 'mongodb://secret-uri',
    },
    () => {
      const resolved = resolveMongoUriFromEnv();
      assert.equal(resolved, 'mongodb://primary-uri');
      assert.equal(process.env.MONGO_URI, 'mongodb://primary-uri');
    }
  );
});

test('resolveMongoUriFromEnv falls back to MONGO_URI_SECRET', () => {
  withEnv(
    {
      MONGO_URI: '   ',
      MONGO_URI_SECRET: '  mongodb://secret-uri  ',
    },
    () => {
      const resolved = resolveMongoUriFromEnv();
      assert.equal(resolved, 'mongodb://secret-uri');
      assert.equal(process.env.MONGO_URI, 'mongodb://secret-uri');
    }
  );
});

test('validateRuntimeEnv throws when Mongo URI is missing', () => {
  withEnv(
    {
      MONGO_URI: undefined,
      MONGO_URI_SECRET: undefined,
      JWT_SECRET: 'present',
      NODE_ENV: 'production',
    },
    () => {
      assert.throws(
        () => validateRuntimeEnv({ isNodeTest: false, nodeEnv: 'production' }),
        /Missing MongoDB URI/
      );
    }
  );
});

test('validateRuntimeEnv throws when JWT_SECRET is missing in non-test mode', () => {
  withEnv(
    {
      MONGO_URI: 'mongodb://present',
      MONGO_URI_SECRET: undefined,
      JWT_SECRET: '   ',
      NODE_ENV: 'production',
    },
    () => {
      assert.throws(
        () => validateRuntimeEnv({ isNodeTest: false, nodeEnv: 'production' }),
        /Missing JWT_SECRET/
      );
    }
  );
});

test('validateRuntimeEnv allows missing JWT_SECRET in test mode', () => {
  withEnv(
    {
      MONGO_URI: 'mongodb://present',
      MONGO_URI_SECRET: undefined,
      JWT_SECRET: undefined,
      NODE_ENV: 'test',
    },
    () => {
      assert.doesNotThrow(() =>
        validateRuntimeEnv({ isNodeTest: true, nodeEnv: 'test' })
      );
    }
  );
});
