/**
 * @module interfaces/http/routes/status
 * Public service status snapshot.
 */

const express = require('express');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createStatusService } = require('../../../modules/status/application/statusService');

/**
 * @param {object} deps
 * @param {*} deps.mongoose
 * @param {*} [deps.io] - Socket.IO server. When present, reports clientsCount.
 * @param {object} [deps.statusService]
 * @param {{ statusLimiter?: any }} [deps.rateLimit]
 * @returns {import('express').Router}
 */
function createStatusRouter(deps = {}) {
  const { mongoose, io, rateLimit = {} } = deps;
  const statusService = deps.statusService || createStatusService({ mongoose, io });

  if (!mongoose) throw new Error('createStatusRouter requires mongoose');

  const router = express.Router();
  const noop = (_req, _res, next) => next();
  const statusLimiter = rateLimit.statusLimiter || noop;

  /**
   * @openapi
   * /status/services:
   *   get:
   *     tags: [Status]
   *     summary: Public service status snapshot
   *     description: |
   *       Lightweight uptime/health snapshot for the frontend status page.
   *       Reports MongoDB connectivity, process uptime, and Socket.IO
   *       connection count.
   *     security: []
   *     responses:
   *       200:
   *         description: Status snapshot
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/ServicesStatusResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   */
  router.get(
    '/status/services',
    statusLimiter,
    async (_req, res, next) => {
      try {
        const status = await statusService.getServicesStatus();
        return res.json({ success: true, ...status });
      } catch (err) {
        if (err && err.status) {
          return sendHttpError(res, err.status, err.message, err.code, err.details);
        }
        return next(err);
      }
    }
  );

  return router;
}

module.exports = { createStatusRouter };
