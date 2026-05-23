const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

/**
 * Per-recipient device fanout outbox. The frontend uploads one ciphertext
 * envelope per recipient device; this router persists them so disconnected
 * devices can pull on connect.
 *
 * IMPORTANT (contract for callers):
 *   - The server NEVER inspects `ciphertext`. All E2E payloads must already
 *     be encrypted by the sender device under a per-recipient DR session.
 *     The previous "device-envelope plaintext relay" pattern is removed —
 *     emitting plaintext here is a frontend bug, not a backend feature.
 *   - The sender device id (`senderDeviceId`) MUST be a device owned by the
 *     authenticated user. The router enforces this when the JWT carries a
 *     deviceId/deviceUserId claim.
 */
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
      {
        field: 'envelopes',
        type: 'array',
        custom: (value) => {
          if (value.length === 0) return 'envelopes must be a non-empty array';
          if (value.length > 256) return 'envelopes batch exceeds 256 entries';
          for (const envelope of value) {
            if (!envelope || typeof envelope !== 'object') return 'envelopes entries must be objects';
            if (typeof envelope.recipientDeviceId !== 'string' || envelope.recipientDeviceId.length === 0) {
              return 'envelopes[].recipientDeviceId is required';
            }
            if (typeof envelope.ciphertext !== 'string' || envelope.ciphertext.length === 0) {
              return 'envelopes[].ciphertext is required';
            }
          }
          return null;
        },
      },
      { field: 'senderDeviceId', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        // Bind sender identity to the authenticated JWT to prevent a client
        // from claiming a sender device it doesn't own. When the JWT carries
        // a deviceId/deviceUserId, the body claim MUST match.
        const claimedDevice = req.user?.deviceId || req.user?.deviceUserId || null;
        const senderDeviceId = String(req.body.senderDeviceId || '').trim();
        if (!senderDeviceId) {
          return sendHttpError(res, 400, 'senderDeviceId is required', 'validation_error', 'senderDeviceId');
        }
        if (claimedDevice && senderDeviceId !== claimedDevice && senderDeviceId !== req.user?.deviceUserId) {
          return sendHttpError(res, 403, 'senderDeviceId does not match the authenticated device', 'envelope_sender_mismatch');
        }

        const result = await deviceManagementService.storeEnvelopes({
          envelopes: req.body.envelopes,
          senderDeviceId,
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
      const requestedDevice = String(req.params.deviceId || '').trim();
      if (!requestedDevice) {
        return sendHttpError(res, 400, 'deviceId is required', 'validation_error', 'deviceId');
      }
      if (req.user.deviceId && req.user.deviceId !== requestedDevice && req.user.deviceUserId !== requestedDevice) {
        return sendHttpError(res, 403, 'Cannot fetch envelopes for another device', 'envelope_forbidden');
      }
      const envelopes = await deviceManagementService.fetchEnvelopes({ deviceId: requestedDevice });
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
        const ackDevice = String(req.body.deviceId || '').trim();
        if (!ackDevice) {
          return sendHttpError(res, 400, 'deviceId is required', 'validation_error', 'deviceId');
        }
        if (req.user.deviceId && req.user.deviceId !== ackDevice && req.user.deviceUserId !== ackDevice) {
          return sendHttpError(res, 403, 'Cannot ack envelopes for another device', 'envelope_forbidden');
        }
        const result = await deviceManagementService.ackEnvelope({
          envelopeId: req.params.envelopeId,
          deviceId: ackDevice,
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
