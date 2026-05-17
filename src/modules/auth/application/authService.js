const crypto = require('crypto');
const { customAlphabet } = require('nanoid');
const {
  ACCESS_TOKEN_TTL,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_BYTES,
} = require('../../../shared/constants');
const { UnauthorizedError, BadRequestError } = require('../../../shared/errors');

/**
 * Hash a refresh token with SHA-256. We store the hash, never the plain token —
 * if the DB leaks, no live session is usable without the plain that only the
 * legitimate client holds.
 */
function hashToken(plain) {
  return crypto.createHash('sha256').update(plain, 'utf8').digest('hex');
}

function generatePlainRefreshToken() {
  return crypto.randomBytes(REFRESH_TOKEN_BYTES).toString('hex');
}

function signAccessToken(jwt, user, secret) {
  return jwt.sign(
    { id: user.id, username: user.username },
    secret,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

/**
 * Application service for authentication use cases. Implements the
 * access-token + rotating-refresh-token pattern with reuse detection.
 *
 * The JWT signing secret is captured at construction time so we fail fast
 * during startup if `JWT_SECRET` is missing in the environment, instead of
 * deferring to the first login (where `jwt.sign(payload, undefined, ...)`
 * surfaces a cryptic error).
 *
 * @param {object} deps
 * @param {*} deps.User - Mongoose User model
 * @param {*} deps.RefreshToken - Mongoose RefreshToken model
 * @param {*} deps.bcrypt
 * @param {*} deps.jwt
 * @param {string} [deps.jwtSecret] - signing secret; defaults to process.env.JWT_SECRET
 * @param {function} deps.normalizeOneTimePreKeysPayload
 * @param {number} deps.OPK_MAX_STORED
 */
function createAuthService({
  User,
  RefreshToken,
  bcrypt,
  jwt,
  jwtSecret,
  normalizeOneTimePreKeysPayload,
  OPK_MAX_STORED,
}) {
  if (!User) throw new Error('createAuthService requires User model');
  if (!bcrypt) throw new Error('createAuthService requires bcrypt');
  if (!jwt) throw new Error('createAuthService requires jwt');
  const secret = jwtSecret || process.env.JWT_SECRET;
  if (!secret || typeof secret !== 'string' || secret.length === 0) {
    throw new Error('createAuthService requires a non-empty jwtSecret (or JWT_SECRET env var)');
  }

  async function issueRefreshToken({ userId, ip, userAgent }) {
    const plain = generatePlainRefreshToken();
    const tokenHash = hashToken(plain);
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000);
    await RefreshToken.create({
      tokenHash,
      userId,
      expiresAt,
      revoked: false,
      ip: ip || null,
      userAgent: userAgent || null,
    });
    return { plain, tokenHash };
  }

  return {
    /**
     * Register a new user account.
     * (Refresh tokens are NOT issued here — caller must POST /auth/login.)
     */
    async register({ username, password, keyBundle, aboutme, profilePicture }) {
      const { publicIdentityKeyX25519, publicIdentityKeyEd25519, publicSignedPreKey, oneTimePreKeys } = keyBundle;
      const [signedPreKey, signature] = publicSignedPreKey;

      const hashedPassword = await bcrypt.hash(password, 10);
      const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 5);
      const id = nanoid();
      const normalizedOpks = normalizeOneTimePreKeysPayload(oneTimePreKeys, OPK_MAX_STORED);

      const user = new User({
        id,
        username,
        hashedPassword,
        publicIdentityKeyX25519,
        publicIdentityKeyEd25519,
        signedPreKey,
        signature,
        signedPreKeyId: 0,
        oneTimePreKeys: normalizedOpks,
        aboutme: typeof aboutme === 'string' ? aboutme : '',
        profilePicture: typeof profilePicture === 'string' ? profilePicture : '',
      });

      await user.save();
      return { userId: id };
    },

    /**
     * Authenticate user, issue access + refresh tokens.
     * @returns {Promise<{ success: true, token, refreshToken, userId, expiresIn } | { success: false, error }>}
     */
    async login({ username, password, ip, userAgent } = {}) {
      const user = await User.findOne({ username });
      if (!user) return { success: false, error: 'Invalid username or password' };

      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) return { success: false, error: 'Invalid username or password' };

      const token = signAccessToken(jwt, user, secret);

      let refreshToken = null;
      if (RefreshToken && typeof RefreshToken.create === 'function') {
        const issued = await issueRefreshToken({ userId: user.id, ip, userAgent });
        refreshToken = issued.plain;
      }

      return {
        success: true,
        token,
        refreshToken,
        userId: user.id,
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      };
    },

    /**
     * Exchange a valid refresh token for a fresh access+refresh pair.
     * Rotates the refresh token (the old one is revoked, the new one stored).
     * On reuse of an already-revoked token, all of the user's refresh tokens
     * are revoked as a compromise signal.
     */
    async refresh({ refreshToken, ip, userAgent } = {}) {
      if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
        throw new BadRequestError('refreshToken is required', 'validation_error');
      }
      if (!RefreshToken || typeof RefreshToken.findOne !== 'function') {
        throw new Error('createAuthService.refresh requires RefreshToken model');
      }

      const tokenHash = hashToken(refreshToken);
      const stored = await RefreshToken.findOne({ tokenHash });
      if (!stored) {
        throw new UnauthorizedError('Refresh token is invalid', 'refresh_token_invalid');
      }

      if (stored.revoked) {
        await RefreshToken.updateMany(
          { userId: stored.userId, revoked: false },
          { $set: { revoked: true, revokedAt: new Date(), reusedAt: new Date() } }
        );
        throw new UnauthorizedError('Refresh token reuse detected', 'refresh_token_reused');
      }

      if (stored.expiresAt instanceof Date && stored.expiresAt.getTime() <= Date.now()) {
        throw new UnauthorizedError('Refresh token has expired', 'refresh_token_expired');
      }

      const user = await User.findOne({ id: stored.userId });
      if (!user) {
        throw new UnauthorizedError('User no longer exists', 'user_not_found');
      }

      const issued = await issueRefreshToken({ userId: stored.userId, ip, userAgent });
      stored.revoked = true;
      stored.revokedAt = new Date();
      stored.replacedBy = issued.tokenHash;
      await stored.save();

      const token = signAccessToken(jwt, user, secret);
      return {
        token,
        refreshToken: issued.plain,
        userId: user.id,
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      };
    },

    /**
     * Revoke a refresh token. Idempotent: returns ok regardless of whether
     * the token existed or was already revoked (so attackers can't probe
     * existence). Bound to the authenticated user — refresh tokens belonging
     * to a different user are silently ignored.
     */
    async logout({ refreshToken, userId } = {}) {
      if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
        throw new BadRequestError('refreshToken is required', 'validation_error');
      }
      if (typeof userId !== 'string' || userId.length === 0) {
        // Without a concrete userId, Mongoose would drop the field from the
        // query and the call would revoke ANY refresh token matching the hash
        // — i.e. another user's. Refuse explicitly.
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (!RefreshToken || typeof RefreshToken.findOneAndUpdate !== 'function') {
        throw new Error('createAuthService.logout requires RefreshToken model');
      }
      const tokenHash = hashToken(refreshToken);
      await RefreshToken.findOneAndUpdate(
        { tokenHash, userId },
        { $set: { revoked: true, revokedAt: new Date() } }
      );
      return { ok: true };
    },
  };
}

module.exports = { createAuthService, hashToken };
