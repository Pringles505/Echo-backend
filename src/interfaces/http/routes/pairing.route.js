const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

function createPairingRouter({ pairingService, mongoose, requireAuth } = {}) {
  if (!pairingService) throw new Error('createPairingRouter requires pairingService');
  if (!mongoose) throw new Error('createPairingRouter requires mongoose');
  if (typeof requireAuth !== 'function') throw new Error('createPairingRouter requires requireAuth');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function handleError(res, next, err) {
    if (err?.status) return sendHttpError(res, err.status, err.message, err.code, err.details);
    return next(err);
  }

  function requestMetadata(req) {
    return {
      ipAddress: req.ip || req.socket?.remoteAddress || null,
      userAgent: req.headers['user-agent'] || null,
    };
  }

  // Primary device creates a pairing QR session
  router.post(
    '/pairing/session',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'primaryDeviceId', type: 'string' },
      { field: 'serverUrl', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const result = await pairingService.createSession({
          parentUserId: req.user.id,
          primaryDeviceId: req.body.primaryDeviceId,
          serverUrl: req.body.serverUrl || null,
        });
        return res.status(201).json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Poll session status (primary polls to see pending request; new device polls for approval)
  router.get('/pairing/session/:sessionId', dbGuard, async (req, res, next) => {
    try {
      const result = await pairingService.getSession({ sessionId: req.params.sessionId });
      return res.json({ success: true, session: result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  // New device submits its public bundle after scanning QR
  router.post(
    '/pairing/request',
    dbGuard,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'newDeviceId', type: 'string' },
      { field: 'newDevicePublicIdentityKeyX25519', type: 'string' },
      { field: 'newDevicePublicIdentityKeyEd25519', type: 'string' },
      { field: 'newDeviceSignedPreKey', type: 'string' },
      { field: 'newDeviceSignedPreKeySignature', type: 'string' },
      { field: 'newDeviceName', type: 'string', required: false },
      { field: 'platform', type: 'string', required: false },
      { field: 'userAgent', type: 'string', required: false },
      { field: 'locale', type: 'string', required: false },
      { field: 'timezone', type: 'string', required: false },
      { field: 'challengeResponse', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const result = await pairingService.submitRequest({
          ...(req.body || {}),
          requestMetadata: requestMetadata(req),
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Primary device approves — signs the new device identity
  router.post(
    '/pairing/approve',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'deviceAuthorizationSignature', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const result = await pairingService.approve({
          sessionId: req.body.sessionId,
          deviceAuthorizationSignature: req.body.deviceAuthorizationSignature || null,
          approverUserId: req.user.id,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Primary device rejects
  router.post(
    '/pairing/reject',
    requireAuth,
    dbGuard,
    validateBody([{ field: 'sessionId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const result = await pairingService.reject({
          sessionId: req.body.sessionId,
          approverUserId: req.user.id,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // New device polls for approval result (returns token when approved)
  router.get('/pairing/poll/:sessionId', dbGuard, async (req, res, next) => {
    try {
      const result = await pairingService.pollResult({ sessionId: req.params.sessionId });
      return res.json({ success: true, ...result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  return router;
}

module.exports = { createPairingRouter };
