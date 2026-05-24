const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createCallsService } = require('../../../modules/calls/application/callsService');

function createCallsRouter(deps = {}) {
  const { mongoose, requireAuth, models, services, notifier } = deps;
  if (!mongoose) throw new Error('createCallsRouter requires mongoose');
  if (typeof requireAuth !== 'function') {
    throw new Error('createCallsRouter requires requireAuth middleware');
  }

  const callsService = deps.callsService || createCallsService({
    Call: models?.Call,
    callEventService: services?.callEventService,
    notifier,
  });

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function handleServiceError(res, next, err) {
    if (err && Number.isInteger(err.status)) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /calls/initiate:
   *   post:
   *     tags: [Calls]
   *     summary: Initiate a call
   *     description: Start a voice/video call with another user.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/InitiateCallRequest'
   *     responses:
   *       200:
   *         description: Call initiated
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CallResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/calls/initiate',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'targetUserId', type: 'string' },
      { field: 'callId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const { targetUserId, callId } = req.body;
        const result = await callsService.initiateCall({
          callerId: req.user.id,
          callerName: req.user.username,
          targetUserId,
          callId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /calls/accept:
   *   post:
   *     tags: [Calls]
   *     summary: Accept an incoming call
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/CallIdRequest'
   *     responses:
   *       200:
   *         description: Call accepted
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CallResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/calls/accept',
    requireAuth,
    dbGuard,
    validateBody([{ field: 'callId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await callsService.acceptCall({
          userId: req.user.id,
          callId: req.body.callId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /calls/decline:
   *   post:
   *     tags: [Calls]
   *     summary: Decline an incoming call
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/CallIdRequest'
   *     responses:
   *       200:
   *         description: Call declined
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CallResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/calls/decline',
    requireAuth,
    dbGuard,
    validateBody([{ field: 'callId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await callsService.declineCall({
          userId: req.user.id,
          callId: req.body.callId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /calls/end:
   *   post:
   *     tags: [Calls]
   *     summary: End an active call
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/CallIdRequest'
   *     responses:
   *       200:
   *         description: Call ended
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CallResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/calls/end',
    requireAuth,
    dbGuard,
    validateBody([{ field: 'callId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await callsService.endCall({
          userId: req.user.id,
          callId: req.body.callId,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /calls/media-state:
   *   post:
   *     tags: [Calls]
   *     summary: Update audio/video media state
   *     description: Forward a media state change to the call peer in real time.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/MediaStateRequest'
   *     responses:
   *       200:
   *         description: Media state forwarded
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/CallResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/calls/media-state',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'targetUserId', type: 'string' },
      {
        field: 'mediaType',
        type: 'string',
        custom: (value) =>
          value === 'audio' || value === 'video'
            ? null
            : "mediaType must be 'audio' or 'video'",
      },
      { field: 'isEnabled', type: 'boolean' },
    ]),
    async (req, res, next) => {
      try {
        const { targetUserId, mediaType, isEnabled } = req.body;
        const result = await callsService.updateMediaState({
          userId: req.user.id,
          targetUserId,
          mediaType,
          isEnabled,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createCallsRouter };
