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

module.exports = { loadEnv };
