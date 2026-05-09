/**
 * @module interfaces/http/routes/messages
 * Direct messaging REST endpoints.
 *
 * Mirrors socket events `checkIfMessagesExist`, `getLatestMessageNumber`
 * and `messageSeen` over HTTP. Side-effects (e.g. `messageSeenUpdate`
 * notifications) are forwarded through the injected `notifier` adapter.
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createMessagingService } = require('../../../modules/messaging/application/messagingService');

/**
 * Resolves the messaging service from explicit DI or builds it from the
 * shared `httpDeps` bundle assembled in `server.js`.
 */
function resolveMessagingService(deps) {
  if (deps?.messagingService) return deps.messagingService;
  const models = deps?.models || {};
  const services = deps?.services || {};
  const sequenceService = services.sequenceService || {};
  return createMessagingService({
    Message: models.Message,
    MessageSequence: models.MessageSequence,
    makeConversationKey: sequenceService.makeConversationKey,
    ensureConversationSequence: sequenceService.ensureConversationSequence,
    notifier: deps?.notifier,
  });
}

/**
 * @param {object} deps
 * @param {object} [deps.messagingService] - Explicit service (preferred for tests)
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} [deps.requireAuth]
 * @returns {import('express').Router}
 */
function createMessagesRouter(deps = {}) {
  const messagingService = resolveMessagingService(deps);
  const { mongoose, requireAuth } = deps;
  if (!mongoose) throw new Error('createMessagesRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const authGuard = typeof requireAuth === 'function'
    ? requireAuth
    : (_req, _res, next) => next();

  const targetUserBodyRules = [{ field: 'targetUserId', type: 'string' }];

  function handleServiceError(res, err, next) {
    if (err?.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /messages/check:
   *   post:
   *     tags: [Messages]
   *     summary: Check if messages exist with another user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/TargetUserRequest'
   *     responses:
   *       200:
   *         description: Existence check result
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CheckMessagesResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/messages/check',
    authGuard,
    dbGuard,
    validateBody(targetUserBodyRules),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { targetUserId } = req.body;
        const { exists } = await messagingService.checkMessagesExist({ userId, targetUserId });
        return res.json({ success: true, exists });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /messages/latest-number:
   *   post:
   *     tags: [Messages]
   *     summary: Get latest accepted message number in a conversation
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/TargetUserRequest'
   *     responses:
   *       200:
   *         description: Latest message number
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/LatestMessageNumberResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/messages/latest-number',
    authGuard,
    dbGuard,
    validateBody(targetUserBodyRules),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { targetUserId } = req.body;
        const { messageNumber } = await messagingService.getLatestMessageNumber({ userId, targetUserId });
        return res.json({ success: true, messageNumber });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /messages/mark-seen:
   *   post:
   *     tags: [Messages]
   *     summary: Mark inbound messages from a peer as seen
   *     description: Updates seen status and emits `messageSeenUpdate` to the peer.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/TargetUserRequest'
   *     responses:
   *       200:
   *         description: Seen status updated
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               required: [success]
   *               properties:
   *                 success: { type: boolean }
   *                 updatedCount: { type: integer }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/messages/mark-seen',
    authGuard,
    dbGuard,
    validateBody(targetUserBodyRules),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { targetUserId } = req.body;
        const { updatedCount } = await messagingService.markMessagesSeen({ userId, targetUserId });
        return res.json({ success: true, updatedCount });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  return router;
}

module.exports = { createMessagesRouter };
