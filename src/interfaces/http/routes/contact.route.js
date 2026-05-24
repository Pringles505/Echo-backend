// Public contact / support submission endpoint. Persists a SupportTicket
// under the hood; the route name follows the public contract.

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createSupportService } = require('../../../modules/support/application/supportService');

function createContactRouter(deps = {}) {
  const {
    mongoose,
    optionalAuth,
    models = {},
    rateLimit = {},
  } = deps;

  const supportService = deps.supportService || createSupportService({
    SupportTicket: models.SupportTicket,
  });

  if (!mongoose) throw new Error('createContactRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const noop = (_req, _res, next) => next();
  const contactLimiter = rateLimit.contactLimiter || noop;
  const auth = typeof optionalAuth === 'function' ? optionalAuth : noop;

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /contact/submit:
   *   post:
   *     tags: [Support]
   *     summary: Submit a contact / support ticket
   *     description: |
   *       Public form for support requests. When called with a valid JWT,
   *       the resulting ticket is linked to the authenticated `userId`.
   *     security: []
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema: { $ref: '#/components/schemas/ContactSubmitRequest' }
   *     responses:
   *       201:
   *         description: Ticket created
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/SupportTicketResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/contact/submit',
    contactLimiter,
    auth,
    dbGuard,
    validateBody([
      { field: 'name', type: 'string' },
      { field: 'email', type: 'string' },
      { field: 'subject', type: 'string' },
      { field: 'message', type: 'string' },
      { field: 'category', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const ticket = await supportService.submitTicket({
          name: req.body.name,
          email: req.body.email,
          subject: req.body.subject,
          message: req.body.message,
          category: req.body.category,
          userId: req.user?.id || null,
          ip: req.ip,
          userAgent: req.headers?.['user-agent'] || null,
        });
        return res.status(201).json({ success: true, ticket });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createContactRouter };
