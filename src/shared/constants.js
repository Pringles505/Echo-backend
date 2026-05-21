/**
 * Centralized configuration constants following DDD and best practices.
 * @module shared/constants
 */

// ============================================================================
// OPK (One-Time Pre-Key) Configuration
// ============================================================================

/** Minimum count before requesting new OPKs */
const OPK_LOW_WATERMARK = 50;

/** Target number of OPKs when re-supplying */
const OPK_TARGET_COUNT = 100;

/** Maximum OPKs stored per user */
const OPK_MAX_STORED = 500;

/** Maximum OPKs uploadable in single request */
const OPK_UPLOAD_MAX = 200;

  // OPK Rate Limiting
/** OPK bundle request rate limit: max 60 requests per 60-second window */
const OPK_BUNDLE_RATE_LIMIT = {
  max: 60,
  windowMs: 60_000, // 60 seconds
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

// ============================================================================
// CORS & Network Configuration
// ============================================================================

/** Allowed origins for CORS requests */
const CORS_ORIGINS = process.env.NODE_ENV === 'production'
  ? [
    'https://chat-tuah-frontend.vercel.app',
    'tauri://localhost',
    'http://tauri.localhost',
    'https://tauri.localhost',
  ]
  : true; // Allow all origins in development (LAN phones, Vite proxy, etc.)

/** Default server port */
const PORT = process.env.PORT || 3001;

/** Versioned API root prefix */
const API_VERSION_PREFIX = '/api/v1';

/** API version header value */
const API_VERSION_HEADER_VALUE = 'v1';

// ============================================================================
// Socket.IO Configuration
// ============================================================================

/** Events that don't require authentication (public gate) */
const PUBLIC_SOCKET_EVENTS = ['register', 'login'];

/** Socket.IO ping interval (ms) */
const SOCKET_PING_INTERVAL = 25_000;

/** Socket.IO ping timeout (ms) */
const SOCKET_PING_TIMEOUT = 60_000;

// ============================================================================
// HTTP Request Configuration
// ============================================================================

/** JSON body size limit for HTTP requests */
const JSON_LIMIT = '15mb';

/** Text body size limit for HTTP requests */
const TEXT_LIMIT = '15mb';

// ============================================================================
// File Upload Configuration
// ============================================================================

/** Max file size for profile pictures (bytes) */
const PROFILE_PICTURE_MAX_SIZE = 5_000_000; // 5 MB

/** Allowed MIME types for profile pictures */
const PROFILE_PICTURE_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
];

/** Upload directory for profile pictures */
const UPLOADS_DIR = 'uploads';

/** Max file size for banner images (bytes) */
const BANNER_MAX_SIZE = 8_000_000; // 8 MB

/** Allowed MIME types for banner images */
const BANNER_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/webp',
];

// ============================================================================
// Blog / Community / Support Configuration
// ============================================================================

/** Maximum slug length for blog posts and events */
const BLOG_SLUG_MAX_LENGTH = 200;

/** Maximum blog title length */
const BLOG_TITLE_MAX_LENGTH = 300;

/** Maximum support ticket message length (characters) */
const SUPPORT_MESSAGE_MAX_LENGTH = 10_000;

/** Maximum support ticket subject length */
const SUPPORT_SUBJECT_MAX_LENGTH = 300;

/** Default page size for paginated event lists */
const EVENT_LIST_DEFAULT_LIMIT = 20;

/** Hard cap for event list pagination */
const EVENT_LIST_MAX_LIMIT = 100;

// ============================================================================
// Message Configuration
// ============================================================================

/** Maximum message length (characters) */
const MAX_MESSAGE_LENGTH = 10_000;

/** Maximum message batch size for history retrieval */
const MAX_MESSAGE_BATCH_SIZE = 100;

// ============================================================================
// Group Configuration
// ============================================================================

/** Minimum members required for group */
const MIN_GROUP_MEMBERS = 2;

/** Maximum members in a group */
const MAX_GROUP_MEMBERS = 1000;

/** Maximum group name length (characters) */
const MAX_GROUP_NAME_LENGTH = 255;

// ============================================================================
// Database Configuration
// ============================================================================

/** MongoDB connection string from environment */
const MONGO_URI = process.env.MONGO_URI;

/** MongoDB test connection string from environment */
const MONGO_URI_TEST = process.env.MONGO_URI_TEST;

/** JWT secret for token signing from environment */
const JWT_SECRET = process.env.JWT_SECRET;

// ============================================================================
// Auth Configuration
// ============================================================================

/** @deprecated Use ACCESS_TOKEN_TTL instead. Retained for backwards compatibility. */
const JWT_EXPIRATION = '1h';

/** Access JWT lifetime. Frontend refreshes proactively via /auth/refresh. */
const ACCESS_TOKEN_TTL = '1h';

/** Same as ACCESS_TOKEN_TTL but in seconds — surfaced to clients as `expiresIn`. */
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;

/** Refresh token lifetime (seconds). MongoDB TTL index deletes after this. */
const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/** Random bytes used to generate the opaque refresh token (hex doubles the length). */
const REFRESH_TOKEN_BYTES = 64;

/** Bcrypt salt rounds for password hashing */
const BCRYPT_SALT_ROUNDS = 10;

// ============================================================================
// Logging Configuration
// ============================================================================

/** Log level (development, production, test) */
const LOG_LEVEL = process.env.NODE_ENV === 'production' ? 'info' : 'debug';

// ============================================================================
// Database TTL Indexes
// ============================================================================

/** TTL for OpkRequestLog documents (seconds) – 30 days */
const OPK_REQUEST_LOG_TTL = 30 * 24 * 60 * 60;

/** TTL for temporary one-time objects (seconds) – 7 days */
const TEMPORARY_OBJECT_TTL = 7 * 24 * 60 * 60;

// ============================================================================
// Exports
// ============================================================================

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
  PORT,
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
  BCRYPT_SALT_ROUNDS,

  // Logging
  LOG_LEVEL,

  // TTL
  OPK_REQUEST_LOG_TTL,
  TEMPORARY_OBJECT_TTL,
};
