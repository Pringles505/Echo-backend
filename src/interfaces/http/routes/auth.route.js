/**
 * @module interfaces/http/routes/auth
 * Authentication HTTP endpoints.
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * @param {object} deps
 * @param {object} deps.authService - createAuthService() instance
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} [deps.registerLimiter]
 * @param {import('express').RequestHandler} [deps.loginLimiter]
 * @returns {import('express').Router}
 */
function createAuthRouter({ authService, mongoose, registerLimiter, loginLimiter } = {}) {
  if (!authService) throw new Error('createAuthRouter requires authService');
  if (!mongoose) throw new Error('createAuthRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  const registerLimit = typeof registerLimiter === 'function' ? registerLimiter : (_req, _res, next) => next();
  const loginLimit = typeof loginLimiter === 'function' ? loginLimiter : (_req, _res, next) => next();

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
   *     summary: Authenticate user and obtain a JWT
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
        const result = await authService.login({ username, password });
        if (!result || result.success === false) {
          return sendHttpError(
            res,
            401,
            result?.error || 'Invalid username or password',
            'invalid_credentials'
          );
        }
        return res.json({ success: true, token: result.token, userId: result.userId });
      } catch (err) {
        if (err?.status) {
          return sendHttpError(res, err.status, err.message, err.code, err.details);
        }
        return next(err);
      }
    }
  );

  return router;
}

module.exports = { createAuthRouter };
