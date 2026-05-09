const express = require('express');

const healthRouter = express.Router();

/**
 * @openapi
 * /health:
 *   get:
 *     tags:
 *       - Health
 *     summary: Liveness probe
 *     description: Returns HTTP 200 when the backend process is up.
 *     responses:
 *       200:
 *         description: Service is alive.
 */
healthRouter.get('/health', (_req, res) => {
  res.sendStatus(200);
});

module.exports = { healthRouter };
