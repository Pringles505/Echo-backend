const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const {
  createEventsService,
} = require('../../../modules/community/application/eventsService');
const {
  createNewsletterService,
} = require('../../../modules/community/application/newsletterService');

function createCommunityRouter(deps = {}) {
  const {
    mongoose,
    requireAuth,
    models = {},
    rateLimit = {},
  } = deps;

  const eventsService = deps.eventsService || createEventsService({
    Event: models.Event,
    EventRegistration: models.EventRegistration,
  });
  const newsletterService = deps.newsletterService || createNewsletterService({
    NewsletterSubscriber: models.NewsletterSubscriber,
  });

  if (!mongoose) throw new Error('createCommunityRouter requires mongoose');
  if (typeof requireAuth !== 'function') {
    throw new Error('createCommunityRouter requires requireAuth middleware');
  }

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const noop = (_req, _res, next) => next();
  const newsletterLimiter = rateLimit.newsletterLimiter || noop;
  const eventRegisterLimiter = rateLimit.eventRegisterLimiter || noop;

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /community/events:
   *   get:
   *     tags: [Community]
   *     summary: List active community events
   *     description: Public list of upcoming community events sorted by start date.
   *     security: []
   *     parameters:
   *       - in: query
   *         name: type
   *         schema:
   *           type: string
   *           enum: [event, hackathon, workshop, meetup]
   *       - in: query
   *         name: status
   *         schema:
   *           type: string
   *           enum: [draft, active, cancelled, ended]
   *         description: Defaults to 'active'.
   *       - in: query
   *         name: page
   *         schema: { type: integer, minimum: 1 }
   *       - in: query
   *         name: limit
   *         schema: { type: integer, minimum: 1, maximum: 100 }
   *     responses:
   *       200:
   *         description: List of events
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/EventListResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.get(
    '/community/events',
    dbGuard,
    async (req, res, next) => {
      try {
        const { type, status, page, limit } = req.query;
        const result = await eventsService.listActiveEvents({ type, status, page, limit });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /community/events/{eventId}/register:
   *   post:
   *     tags: [Community]
   *     summary: Register the authenticated user for an event
   *     parameters:
   *       - in: path
   *         name: eventId
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       200:
   *         description: Registration successful
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/EventRegisterResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/community/events/:eventId/register',
    requireAuth,
    eventRegisterLimiter,
    dbGuard,
    async (req, res, next) => {
      try {
        const { eventId } = req.params;
        const userId = req.user?.id;
        const result = await eventsService.registerForEvent({ eventId, userId });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /community/subscribe:
   *   post:
   *     tags: [Community]
   *     summary: Subscribe to the "Sealed Mail" newsletter
   *     description: Public, anonymous newsletter signup. Idempotent by email.
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema: { $ref: '#/components/schemas/NewsletterSubscribeRequest' }
   *     responses:
   *       200:
   *         description: Subscription saved
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/NewsletterSubscribeResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/community/subscribe',
    newsletterLimiter,
    dbGuard,
    validateBody([
      { field: 'email', type: 'string' },
      { field: 'source', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const { email, source } = req.body;
        const result = await newsletterService.subscribe({
          email,
          source,
          ip: req.ip,
          userAgent: req.headers?.['user-agent'] || null,
        });
        return res.json({ success: true, subscriber: result });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createCommunityRouter };
