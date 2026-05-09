/**
 * @module interfaces/http/routes/contacts
 * Friend / contact management REST endpoints.
 *
 * Backed by `contactsService`. The OpenAPI `FriendRequest` schema uses
 * `friendId` (NOT `targetUserId`) — that is the canonical request field.
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const {
  createContactsService,
} = require('../../../modules/contacts/application/contactsService');

/**
 * @param {object} deps
 * @param {object} [deps.contactsService] - Pre-built service. When omitted, a
 *   default one is built from `models.User` + `notifier` so server.js can pass
 *   its `httpDeps` blob unchanged.
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} deps.requireAuth
 * @param {{ emitToUser?: function }} [deps.notifier]
 * @param {{ User: any }} [deps.models]
 * @returns {import('express').Router}
 */
function createContactsRouter(deps = {}) {
  const { mongoose, requireAuth, notifier, models = {} } = deps;

  const contactsService = deps.contactsService || createContactsService({
    User: models.User,
    notifier,
  });

  if (!mongoose) throw new Error('createContactsRouter requires mongoose');
  if (typeof requireAuth !== 'function') {
    throw new Error('createContactsRouter requires requireAuth middleware');
  }

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /contacts/add-friend:
   *   post:
   *     tags: [Contacts]
   *     summary: Add a user to the authenticated user's friend list
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/FriendRequest'
   *     responses:
   *       200:
   *         description: Friend added
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/SuccessResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/contacts/add-friend',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'friendId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { friendId } = req.body;
        await contactsService.addFriend({ userId, friendId });
        return res.json({ success: true });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /contacts/remove-friend:
   *   post:
   *     tags: [Contacts]
   *     summary: Remove a user from the authenticated user's friend list
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/FriendRequest'
   *     responses:
   *       200:
   *         description: Friend removed
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/SuccessResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/contacts/remove-friend',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'friendId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { friendId } = req.body;
        await contactsService.removeFriend({ userId, friendId });
        return res.json({ success: true });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createContactsRouter };
