const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

/**
 * Loads environment variables with test-aware precedence.
 * When running with `node --test`, `.env.test` is preferred if present.
 */
function loadEnv() {
  const envTestPath = path.join(process.cwd(), '.env.test');
  const runningNodeTest = process.argv.includes('--test');

  if (runningNodeTest && fs.existsSync(envTestPath)) {
    dotenv.config({ path: envTestPath });
    return;
  }

  dotenv.config();
}

function resolveMongoUriFromEnv() {
  const explicitMongoUri = typeof process.env.MONGO_URI === 'string'
    ? process.env.MONGO_URI.trim()
    : '';
  if (explicitMongoUri) {
    process.env.MONGO_URI = explicitMongoUri;
    return explicitMongoUri;
  }

  const secretMongoUri = typeof process.env.MONGO_URI_SECRET === 'string'
    ? process.env.MONGO_URI_SECRET.trim()
    : '';
  if (secretMongoUri) {
    process.env.MONGO_URI = secretMongoUri;
    return secretMongoUri;
  }

  return '';
}

/**
 * Validates critical runtime environment variables.
 * In test mode, JWT_SECRET may be injected by tests after dotenv load.
 */
function validateRuntimeEnv(options = {}) {
  const {
    isNodeTest = process.argv.includes('--test'),
    nodeEnv = process.env.NODE_ENV,
  } = options;
  const mongoUri = resolveMongoUriFromEnv();
  if (!mongoUri) {
    throw new Error('Missing MongoDB URI. Set MONGO_URI or MONGO_URI_SECRET.');
  }

  const isTestEnv = String(nodeEnv || '').toLowerCase() === 'test';
  const jwtSecret = typeof process.env.JWT_SECRET === 'string'
    ? process.env.JWT_SECRET.trim()
    : '';

  if (!isNodeTest && !isTestEnv && !jwtSecret) {
    throw new Error('Missing JWT_SECRET. Refusing to start without token signing secret.');
  }
}

module.exports = { loadEnv, resolveMongoUriFromEnv, validateRuntimeEnv };
