/**
 * @module interfaces/http/routes/keys
 * Signal Protocol pre-key and One-Time Pre-Key (OPK) REST endpoints.
 *
 * Mirrors `src/interfaces/socket/handlers/opk.handlers.js` so HTTP and
 * Socket.IO clients see the same outcomes (including OPK consumption,
 * lease reuse, and multi-bucket rate limiting).
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * Build the Keys router.
 *
 * @param {object} deps
 * @param {object} deps.keysService - createKeysService() instance
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} [deps.requireAuth] - JWT auth middleware
 * @param {import('express').RequestHandler} [deps.keyBundleLimiter] - express-rate-limit (60/min) for /keys/bundle
 * @returns {import('express').Router}
 */
function createKeysRouter({ keysService, mongoose, requireAuth, keyBundleLimiter } = {}) {
  if (!keysService) throw new Error('createKeysRouter requires keysService');
  if (!mongoose) throw new Error('createKeysRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const auth = typeof requireAuth === 'function' ? requireAuth : (_req, _res, next) => next();
  const bundleLimit =
    typeof keyBundleLimiter === 'function' ? keyBundleLimiter : (_req, _res, next) => next();

  function handleServiceError(err, res, next) {
    if (err && Number.isInteger(err.status)) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /keys/signed-prekey:
   *   post:
   *     tags: [Keys]
   *     summary: Get signed pre-key for a user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/KeyBundleRequest'
   *     responses:
   *       200:
   *         description: Signed pre-key
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/SignedPreKeyResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/keys/signed-prekey',
    auth,
    dbGuard,
    validateBody([{ field: 'targetUserId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await keysService.getSignedPreKey({ targetUserId: req.body.targetUserId });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(err, res, next);
      }
    }
  );

  /**
   * @openapi
   * /keys/identity/x25519:
   *   post:
   *     tags: [Keys]
   *     summary: Get X25519 identity public key for a user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/KeyBundleRequest'
   *     responses:
   *       200:
   *         description: Identity key
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/IdentityKeyResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/keys/identity/x25519',
    auth,
    dbGuard,
    validateBody([{ field: 'targetUserId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await keysService.getIdentityKeyX25519({
          targetUserId: req.body.targetUserId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(err, res, next);
      }
    }
  );

  /**
   * @openapi
   * /keys/identity/ed25519:
   *   post:
   *     tags: [Keys]
   *     summary: Get Ed25519 identity public key for a user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/KeyBundleRequest'
   *     responses:
   *       200:
   *         description: Identity key
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/IdentityKeyResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/keys/identity/ed25519',
    auth,
    dbGuard,
    validateBody([{ field: 'targetUserId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await keysService.getIdentityKeyEd25519({
          targetUserId: req.body.targetUserId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(err, res, next);
      }
    }
  );

  /**
   * @openapi
   * /keys/bundle:
   *   post:
   *     tags: [Keys]
   *     summary: Get a complete pre-key bundle for a user
   *     description: |
   *       Atomically consumes one OPK if available. Subject to layered
   *       in-memory rate limiting in addition to the per-IP express
   *       limiter.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/KeyBundleRequest'
   *     responses:
   *       200:
   *         description: Pre-key bundle
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/PreKeyBundleResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/keys/bundle',
    auth,
    bundleLimit,
    dbGuard,
    validateBody([{ field: 'targetUserId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const requesterId = req.user?.id;
        const ip = req.ip || '';
        const userAgent = req.get('user-agent') || '';
        const { bundle } = await keysService.getPreKeyBundle({
          requesterId,
          targetUserId: req.body.targetUserId,
          ip,
          userAgent,
        });
        return res.json({ success: true, bundle });
      } catch (err) {
        return handleServiceError(err, res, next);
      }
    }
  );

  /**
   * @openapi
   * /keys/opk/upload:
   *   post:
   *     tags: [Keys]
   *     summary: Upload one-time pre-keys for the authenticated user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/OPKUploadRequest'
   *     responses:
   *       200:
   *         description: OPKs uploaded
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/OPKUploadResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/keys/opk/upload',
    auth,
    dbGuard,
    validateBody([{ field: 'oneTimePreKeys', type: 'array' }]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { stored } = await keysService.uploadOneTimePreKeys({
          userId,
          oneTimePreKeys: req.body.oneTimePreKeys,
        });
        return res.json({ success: true, stored });
      } catch (err) {
        return handleServiceError(err, res, next);
      }
    }
  );

  /**
   * @openapi
   * /keys/opk/status:
   *   get:
   *     tags: [Keys]
   *     summary: Get OPK pool status for the authenticated user
   *     responses:
   *       200:
   *         description: OPK status
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/OPKStatusResponse'
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.get('/keys/opk/status', auth, dbGuard, async (req, res, next) => {
    try {
      const userId = req.user?.id;
      const result = await keysService.getOpkStatus({ userId });
      return res.json({ success: true, ...result });
    } catch (err) {
      return handleServiceError(err, res, next);
    }
  });

  return router;
}

module.exports = { createKeysRouter };
