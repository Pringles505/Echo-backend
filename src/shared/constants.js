/**
 * Centralized configuration constants.
 *
 * All values that operations might need to tune (TTLs, limits, CORS, etc.)
 * read from process.env first and fall back to sensible defaults baked into
 * this file. See `.env.example` in the repo root for the full menu.
 *
 * Code paths that *must* exist regardless of env (server.js boot, tests)
 * can rely on the defaults — no env file is required for the unit tests to
 * pass against in-memory or local Mongo.
 *
 * @module shared/constants
 */

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

function parseIntEnv(name, fallback) {
  const raw = process.env[name];
  if (typeof raw !== 'string') return fallback;
  const trimmed = raw.trim();
  if (!trimmed) return fallback;
  const parsed = Number.parseInt(trimmed, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function parseStringEnv(name, fallback) {
  const raw = process.env[name];
  if (typeof raw !== 'string') return fallback;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function parseListEnv(name) {
  const raw = process.env[name];
  if (typeof raw !== 'string') return [];
  return raw
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// OPK (One-Time Pre-Key) Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** Minimum count before requesting new OPKs */
const OPK_LOW_WATERMARK = parseIntEnv('OPK_LOW_WATERMARK', 50);

/** Target number of OPKs when re-supplying */
const OPK_TARGET_COUNT = parseIntEnv('OPK_TARGET_COUNT', 100);

/** Maximum OPKs stored per user */
const OPK_MAX_STORED = parseIntEnv('OPK_MAX_STORED', 500);

/** Maximum OPKs uploadable in single request */
const OPK_UPLOAD_MAX = parseIntEnv('OPK_UPLOAD_MAX', 200);

/** OPK bundle request rate limit: max 60 requests per 60-second window */
const OPK_BUNDLE_RATE_LIMIT = {
  max: 60,
  windowMs: 60_000,
};

/** OPK bundle rate limits for different operations */
const OPK_BUNDLE_LIMITS = {
  requesterRequests: { max: 60, windowMs: 60_000 },
  pairRequests: { max: 10, windowMs: 60_000 },
  targetRequests: { max: 60, windowMs: 60_000 },
  requesterConsumes: { max: 30, windowMs: 60_000 },
  targetConsumes: { max: 30, windowMs: 60_000 },
  pairLeaseMs: 60_000,
};

// ─────────────────────────────────────────────────────────────────────────────
// CORS & Network Configuration
// ─────────────────────────────────────────────────────────────────────────────

const CORS_EXTRA_ORIGINS = parseListEnv('CORS_EXTRA_ORIGINS');
const CORS_ALLOWED_ORIGINS = parseListEnv('CORS_ALLOWED_ORIGINS');

/**
 * Allowed origins for CORS requests.
 *
 * Precedence (highest first):
 *   1. `CORS_ALLOWED_ORIGINS` (full explicit list, used in BOTH dev and prod).
 *   2. Production default list + `CORS_EXTRA_ORIGINS` (legacy alias).
 *   3. Development: allow any origin (`true`) so LAN phones, Vite proxy
 *      and Tauri dev windows just work.
 */
const PRODUCTION_DEFAULT_ORIGINS = [
  'https://chat-tuah-frontend.vercel.app',
  'tauri://localhost',
  'http://tauri.localhost',
  'https://tauri.localhost',
];

let CORS_ORIGINS;
if (CORS_ALLOWED_ORIGINS.length > 0) {
  CORS_ORIGINS = CORS_ALLOWED_ORIGINS;
} else if (process.env.NODE_ENV === 'production') {
  CORS_ORIGINS = [...PRODUCTION_DEFAULT_ORIGINS, ...CORS_EXTRA_ORIGINS];
} else {
  CORS_ORIGINS = true;
}

/** Default server port */
const PORT = parseIntEnv('PORT', 3001);

/** Optional bind address (most deployments leave this unset for 0.0.0.0) */
const HOST = parseStringEnv('HOST', '0.0.0.0');

/** Versioned API root prefix */
const API_VERSION_PREFIX = '/api/v1';

/** API version header value */
const API_VERSION_HEADER_VALUE = 'v1';

// ─────────────────────────────────────────────────────────────────────────────
// Socket.IO Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** Events that don't require authentication (public gate) */
const PUBLIC_SOCKET_EVENTS = ['register', 'login'];

/** Socket.IO ping interval (ms) */
const SOCKET_PING_INTERVAL = parseIntEnv('SOCKET_PING_INTERVAL_MS', 25_000);

/** Socket.IO ping timeout (ms) */
const SOCKET_PING_TIMEOUT = parseIntEnv('SOCKET_PING_TIMEOUT_MS', 60_000);

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Request Configuration
// ─────────────────────────────────────────────────────────────────────────────

const JSON_LIMIT = parseStringEnv('JSON_LIMIT', '15mb');
const TEXT_LIMIT = parseStringEnv('TEXT_LIMIT', '15mb');

// ─────────────────────────────────────────────────────────────────────────────
// File Upload Configuration
// ─────────────────────────────────────────────────────────────────────────────

const PROFILE_PICTURE_MAX_SIZE = parseIntEnv('PROFILE_PICTURE_MAX_SIZE', 5_000_000);

const PROFILE_PICTURE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const UPLOADS_DIR = parseStringEnv('UPLOADS_DIR', 'uploads');

const BANNER_MAX_SIZE = parseIntEnv('BANNER_MAX_SIZE', 8_000_000);

const BANNER_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

// ─────────────────────────────────────────────────────────────────────────────
// Blog / Community / Support Configuration
// ─────────────────────────────────────────────────────────────────────────────

const BLOG_SLUG_MAX_LENGTH = 200;
const BLOG_TITLE_MAX_LENGTH = 300;
const SUPPORT_MESSAGE_MAX_LENGTH = 10_000;
const SUPPORT_SUBJECT_MAX_LENGTH = 300;
const EVENT_LIST_DEFAULT_LIMIT = 20;
const EVENT_LIST_MAX_LIMIT = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Message Configuration
// ─────────────────────────────────────────────────────────────────────────────

const MAX_MESSAGE_LENGTH = 10_000;
const MAX_MESSAGE_BATCH_SIZE = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Group Configuration
// ─────────────────────────────────────────────────────────────────────────────

const MIN_GROUP_MEMBERS = 2;
const MAX_GROUP_MEMBERS = 1000;
const MAX_GROUP_NAME_LENGTH = 255;

// ─────────────────────────────────────────────────────────────────────────────
// Database Configuration
// ─────────────────────────────────────────────────────────────────────────────

const MONGO_URI = process.env.MONGO_URI;
const MONGO_URI_TEST = process.env.MONGO_URI_TEST;
const JWT_SECRET = process.env.JWT_SECRET;

// ─────────────────────────────────────────────────────────────────────────────
// Auth Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** @deprecated Use ACCESS_TOKEN_TTL instead. Retained for backwards compatibility. */
const JWT_EXPIRATION = parseStringEnv('JWT_ACCESS_TTL', '1h');

/** Access JWT lifetime. Frontend refreshes proactively via /auth/refresh. */
const ACCESS_TOKEN_TTL = parseStringEnv('JWT_ACCESS_TTL', '1h');

/**
 * Same as ACCESS_TOKEN_TTL but in seconds — surfaced to clients as `expiresIn`.
 * Defaults to 3600 (1h) when JWT_ACCESS_TTL_SECONDS isn't explicitly set.
 */
const ACCESS_TOKEN_TTL_SECONDS = parseIntEnv('JWT_ACCESS_TTL_SECONDS', 60 * 60);

/** Refresh token lifetime (seconds). MongoDB TTL index deletes after this. */
const REFRESH_TOKEN_TTL_SECONDS = parseIntEnv(
  'JWT_REFRESH_TTL_SECONDS',
  30 * 24 * 60 * 60
);

/** Random bytes used to generate the opaque refresh token. */
const REFRESH_TOKEN_BYTES = parseIntEnv('REFRESH_TOKEN_BYTES', 64);

/** Long-lived JWT for device-bound sessions (pairing/sync issued). */
const DEVICE_TOKEN_TTL = parseStringEnv('JWT_DEVICE_TTL', '30d');

/** Bcrypt salt rounds for password hashing */
const BCRYPT_SALT_ROUNDS = parseIntEnv('BCRYPT_SALT_ROUNDS', 10);

// ─────────────────────────────────────────────────────────────────────────────
// Logging Configuration
// ─────────────────────────────────────────────────────────────────────────────

const LOG_LEVEL = parseStringEnv(
  'LOG_LEVEL',
  process.env.NODE_ENV === 'production' ? 'info' : 'debug'
);

// ─────────────────────────────────────────────────────────────────────────────
// Database TTL Indexes
// ─────────────────────────────────────────────────────────────────────────────

/** TTL for OpkRequestLog documents (seconds) – default 30 days */
const OPK_REQUEST_LOG_TTL = parseIntEnv('OPK_REQUEST_LOG_TTL_SECONDS', 60 * 60 * 24 * 30);

/** TTL for temporary one-time objects (seconds) – default 7 days */
const TEMPORARY_OBJECT_TTL = parseIntEnv('TEMPORARY_OBJECT_TTL_SECONDS', 60 * 60 * 24 * 7);

// ─────────────────────────────────────────────────────────────────────────────
// Pairing Configuration
// ─────────────────────────────────────────────────────────────────────────────

/** Pairing session lifetime in milliseconds (default 5 minutes) */
const PAIRING_SESSION_TTL_MS = parseIntEnv('PAIRING_SESSION_TTL_MS', 5 * 60 * 1000);

/**
 * Length of the human-readable pairing code. Minimum enforced at 8 alphanumeric
 * (~40 bits entropy on a 32-character alphabet) regardless of env value.
 */
const PAIRING_CODE_LENGTH = Math.max(parseIntEnv('PAIRING_CODE_LENGTH', 8), 8);

/** Maximum approval attempts before a session is treated as compromised (reserved). */
const PAIRING_MAX_ATTEMPTS = parseIntEnv('PAIRING_MAX_ATTEMPTS', 5);

// ─────────────────────────────────────────────────────────────────────────────
// Device Sync Configuration
// ─────────────────────────────────────────────────────────────────────────────

const SYNC_SESSION_TTL_MS = parseIntEnv('SYNC_SESSION_TTL_MS', 90_000);
const SYNC_SESSION_MAX_TTL_MS = parseIntEnv('SYNC_SESSION_MAX_TTL_MS', 120_000);
const SYNC_CHUNK_MAX_SIZE = parseIntEnv('SYNC_CHUNK_MAX_SIZE', 256 * 1024);
const SYNC_CHUNK_MAX_COUNT = parseIntEnv('SYNC_CHUNK_MAX_COUNT', 256);
const SYNC_MAX_TOTAL_BYTES = parseIntEnv('SYNC_MAX_TOTAL_BYTES', 32 * 1024 * 1024);

// ─────────────────────────────────────────────────────────────────────────────
// Device Envelope Configuration
// ─────────────────────────────────────────────────────────────────────────────

const DEVICE_ENVELOPE_TTL_SECONDS = parseIntEnv(
  'DEVICE_ENVELOPE_TTL_SECONDS',
  60 * 60 * 24 * 7
);
const DEVICE_MAX_PER_USER = parseIntEnv('DEVICE_MAX_PER_USER', 10);
const RATE_LIMIT_ENVELOPES_PER_MIN = parseIntEnv('RATE_LIMIT_ENVELOPES_PER_MIN', 120);

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limit Configuration (consumed by middleware/rateLimit.js)
// ─────────────────────────────────────────────────────────────────────────────

const RATE_LIMIT_AUTH_PER_MIN = parseIntEnv('RATE_LIMIT_AUTH_PER_MIN', 10);
const RATE_LIMIT_REGISTER_PER_HOUR = parseIntEnv('RATE_LIMIT_REGISTER_PER_HOUR', 5);
const RATE_LIMIT_REFRESH_PER_MIN = parseIntEnv('RATE_LIMIT_REFRESH_PER_MIN', 30);
const RATE_LIMIT_PAIRING_PER_MIN = parseIntEnv('RATE_LIMIT_PAIRING_PER_MIN', 30);
const RATE_LIMIT_SYNC_CREATE_PER_MIN = parseIntEnv('RATE_LIMIT_SYNC_CREATE_PER_MIN', 10);
const RATE_LIMIT_SYNC_ATTACH_PER_MIN = parseIntEnv('RATE_LIMIT_SYNC_ATTACH_PER_MIN', 20);

// ─────────────────────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  // OPK
  OPK_LOW_WATERMARK,
  OPK_TARGET_COUNT,
  OPK_MAX_STORED,
  OPK_UPLOAD_MAX,
  OPK_BUNDLE_RATE_LIMIT,
  OPK_BUNDLE_LIMITS,

  // CORS & Network
  CORS_ORIGINS,
  CORS_ALLOWED_ORIGINS,
  CORS_EXTRA_ORIGINS,
  PORT,
  HOST,
  API_VERSION_PREFIX,
  API_VERSION_HEADER_VALUE,

  // Socket.IO
  PUBLIC_SOCKET_EVENTS,
  SOCKET_PING_INTERVAL,
  SOCKET_PING_TIMEOUT,

  // HTTP
  JSON_LIMIT,
  TEXT_LIMIT,

  // File Upload
  PROFILE_PICTURE_MAX_SIZE,
  PROFILE_PICTURE_MIME_TYPES,
  UPLOADS_DIR,
  BANNER_MAX_SIZE,
  BANNER_MIME_TYPES,

  // Blog / Community / Support
  BLOG_SLUG_MAX_LENGTH,
  BLOG_TITLE_MAX_LENGTH,
  SUPPORT_MESSAGE_MAX_LENGTH,
  SUPPORT_SUBJECT_MAX_LENGTH,
  EVENT_LIST_DEFAULT_LIMIT,
  EVENT_LIST_MAX_LIMIT,

  // Messages
  MAX_MESSAGE_LENGTH,
  MAX_MESSAGE_BATCH_SIZE,

  // Groups
  MIN_GROUP_MEMBERS,
  MAX_GROUP_MEMBERS,
  MAX_GROUP_NAME_LENGTH,

  // Database
  MONGO_URI,
  MONGO_URI_TEST,
  JWT_SECRET,

  // Auth
  JWT_EXPIRATION,
  ACCESS_TOKEN_TTL,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_BYTES,
  DEVICE_TOKEN_TTL,
  BCRYPT_SALT_ROUNDS,

  // Logging
  LOG_LEVEL,

  // TTL
  OPK_REQUEST_LOG_TTL,
  TEMPORARY_OBJECT_TTL,

  // Pairing
  PAIRING_SESSION_TTL_MS,
  PAIRING_CODE_LENGTH,
  PAIRING_MAX_ATTEMPTS,

  // Device Sync
  SYNC_SESSION_TTL_MS,
  SYNC_SESSION_MAX_TTL_MS,
  SYNC_CHUNK_MAX_SIZE,
  SYNC_CHUNK_MAX_COUNT,
  SYNC_MAX_TOTAL_BYTES,

  // Device Envelopes
  DEVICE_ENVELOPE_TTL_SECONDS,
  DEVICE_MAX_PER_USER,
  RATE_LIMIT_ENVELOPES_PER_MIN,

  // Rate Limits
  RATE_LIMIT_AUTH_PER_MIN,
  RATE_LIMIT_REGISTER_PER_HOUR,
  RATE_LIMIT_REFRESH_PER_MIN,
  RATE_LIMIT_PAIRING_PER_MIN,
  RATE_LIMIT_SYNC_CREATE_PER_MIN,
  RATE_LIMIT_SYNC_ATTACH_PER_MIN,
};
