/**
 * @module interfaces/http/routes/auth
 * Authentication HTTP endpoints (register, login, refresh, logout).
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * @param {object} deps
 * @param {object} deps.authService - createAuthService() instance
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} [deps.requireAuth] - required for /auth/logout
 * @param {import('express').RequestHandler} [deps.registerLimiter]
 * @param {import('express').RequestHandler} [deps.loginLimiter]
 * @param {import('express').RequestHandler} [deps.refreshLimiter]
 * @returns {import('express').Router}
 */
function createAuthRouter({
  authService,
  mongoose,
  requireAuth,
  registerLimiter,
  loginLimiter,
  refreshLimiter,
} = {}) {
  if (!authService) throw new Error('createAuthRouter requires authService');
  if (!mongoose) throw new Error('createAuthRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const noop = (_req, _res, next) => next();

  const registerLimit = typeof registerLimiter === 'function' ? registerLimiter : noop;
  const loginLimit = typeof loginLimiter === 'function' ? loginLimiter : noop;
  const refreshLimit = typeof refreshLimiter === 'function' ? refreshLimiter : noop;
  const auth = typeof requireAuth === 'function' ? requireAuth : noop;

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /auth/register:
   *   post:
   *     tags: [Authentication]
   *     summary: Create a new user account
   *     description: Registers a user with a Signal Protocol key bundle.
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/RegisterRequest'
   *     responses:
   *       201:
   *         description: Account created
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/RegisterResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/auth/register',
    registerLimit,
    dbGuard,
    validateBody([
      { field: 'username', type: 'string' },
      { field: 'password', type: 'string' },
      { field: 'keyBundle', type: 'object' },
    ]),
    async (req, res, next) => {
      try {
        const { username, password, keyBundle, aboutme, profilePicture } = req.body;
        const { userId } = await authService.register({
          username,
          password,
          keyBundle,
          aboutme,
          profilePicture,
        });
        return res.status(201).json({ success: true, userId });
      } catch (err) {
        if (err?.code === 11000 && err?.keyPattern?.username) {
          return sendHttpError(res, 409, 'Username already taken', 'username_conflict');
        }
        if (err?.status) {
          return sendHttpError(res, err.status, err.message, err.code, err.details);
        }
        return next(err);
      }
    }
  );

  /**
   * @openapi
   * /auth/login:
   *   post:
   *     tags: [Authentication]
   *     summary: Authenticate user and obtain access + refresh tokens
   *     description: |
   *       Returns a short-lived access token (1h) and a long-lived refresh
   *       token (30d). Frontends should persist both. When the access token
   *       expires, call POST /auth/refresh with the refresh token to obtain
   *       a new pair (the refresh token rotates on every use).
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/LoginRequest'
   *     responses:
   *       200:
   *         description: Authentication successful
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/LoginResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/auth/login',
    loginLimit,
    dbGuard,
    validateBody([
      { field: 'username', type: 'string' },
      { field: 'password', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const { username, password } = req.body;
        const result = await authService.login({
          username,
          password,
          ip: req.ip,
          userAgent: req.headers?.['user-agent'] || null,
        });
        if (!result || result.success === false) {
          return sendHttpError(
            res,
            401,
            result?.error || 'Invalid username or password',
            'invalid_credentials'
          );
        }
        const payload = {
          success: true,
          token: result.token,
          userId: result.userId,
        };
        if (result.refreshToken) payload.refreshToken = result.refreshToken;
        if (result.expiresIn) payload.expiresIn = result.expiresIn;
        return res.json(payload);
      } catch (err) {
        if (err?.status) {
          return sendHttpError(res, err.status, err.message, err.code, err.details);
        }
        return next(err);
      }
    }
  );

  /**
   * @openapi
   * /auth/refresh:
   *   post:
   *     tags: [Authentication]
   *     summary: Exchange a refresh token for a fresh access+refresh pair
   *     description: |
   *       The refresh token rotates on every use. The old token is revoked
   *       and a new one is emitted. Reusing an already-revoked refresh token
   *       triggers revocation of ALL refresh tokens for that user (compromise
   *       signal — the legitimate client must log in again).
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/RefreshRequest'
   *     responses:
   *       200:
   *         description: Tokens refreshed
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/RefreshResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/auth/refresh',
    refreshLimit,
    dbGuard,
    validateBody([{ field: 'refreshToken', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await authService.refresh({
          refreshToken: req.body.refreshToken,
          ip: req.ip,
          userAgent: req.headers?.['user-agent'] || null,
        });
        return res.json({
          success: true,
          token: result.token,
          refreshToken: result.refreshToken,
          userId: result.userId,
          expiresIn: result.expiresIn,
        });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /auth/logout:
   *   post:
   *     tags: [Authentication]
   *     summary: Revoke a refresh token (sign out the current device)
   *     description: |
   *       Idempotent: always returns 200 regardless of whether the token
   *       existed or was already revoked, to avoid leaking token existence.
   *       Requires a valid access token in the Authorization header.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/LogoutRequest'
   *     responses:
   *       200:
   *         description: Logged out
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/SuccessResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/auth/logout',
    auth,
    dbGuard,
    validateBody([{ field: 'refreshToken', type: 'string' }]),
    async (req, res, next) => {
      try {
        await authService.logout({
          refreshToken: req.body.refreshToken,
          userId: req.user?.id,
        });
        return res.json({ success: true });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createAuthRouter };
