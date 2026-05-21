const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

function createEnvelopesRouter({ deviceManagementService, mongoose, requireAuth } = {}) {
  if (!deviceManagementService) throw new Error('createEnvelopesRouter requires deviceManagementService');
  if (!mongoose) throw new Error('createEnvelopesRouter requires mongoose');
  if (typeof requireAuth !== 'function') throw new Error('createEnvelopesRouter requires requireAuth');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function handleError(res, next, err) {
    if (err?.status) return sendHttpError(res, err.status, err.message, err.code, err.details);
    return next(err);
  }

  // Store a batch of encrypted envelopes (one per recipient device)
  router.post(
    '/messages/envelopes',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'envelopes', type: 'array' },
      { field: 'senderDeviceId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const result = await deviceManagementService.storeEnvelopes({
          envelopes: req.body.envelopes,
          senderDeviceId: req.body.senderDeviceId,
          logicalSenderId: req.user.id,
        });
        return res.status(201).json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Fetch pending envelopes for the current device
  router.get('/messages/envelopes/:deviceId', requireAuth, dbGuard, async (req, res, next) => {
    try {
      // Only allow fetching own device's envelopes
      if (req.user.deviceId && req.user.deviceId !== req.params.deviceId) {
        return sendHttpError(res, 403, 'Cannot fetch envelopes for another device', 'envelope_forbidden');
      }
      const envelopes = await deviceManagementService.fetchEnvelopes({ deviceId: req.params.deviceId });
      return res.json({ success: true, envelopes });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  // Acknowledge delivery or read status
  router.post(
    '/messages/envelopes/:envelopeId/ack',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'status', type: 'string', required: false },
      { field: 'deviceId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const result = await deviceManagementService.ackEnvelope({
          envelopeId: req.params.envelopeId,
          deviceId: req.body.deviceId,
          status: req.body.status || 'delivered',
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createEnvelopesRouter };
