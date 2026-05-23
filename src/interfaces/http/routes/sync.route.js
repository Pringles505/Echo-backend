const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

function createSyncRouter({ deviceSyncService, mongoose, requireAuth, optionalAuth, syncCreateLimiter, syncAttachLimiter } = {}) {
  if (!deviceSyncService) throw new Error('createSyncRouter requires deviceSyncService');
  if (!mongoose) throw new Error('createSyncRouter requires mongoose');
  if (typeof requireAuth !== 'function') throw new Error('createSyncRouter requires requireAuth');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const createLimit = typeof syncCreateLimiter === 'function' ? syncCreateLimiter : (_req, _res, next) => next();
  const attachLimit = typeof syncAttachLimiter === 'function' ? syncAttachLimiter : (_req, _res, next) => next();

  // Resolve the target session token in this preference order:
  //   1. `X-Sync-Target-Token` header              (preferred — not logged by
  //                                                 most reverse proxies)
  //   2. `Authorization: Bearer sync:<token>`       (interop fallback for
  //                                                 environments that strip
  //                                                 custom headers)
  //   3. `req.body.targetAccessToken`               (POST callers)
  //   4. `req.query.targetAccessToken`              (LEGACY — emit a header
  //                                                 instead; query strings
  //                                                 land in HTTP access logs
  //                                                 and CDN trace logs)
  //
  // After resolution we delete `req.query.targetAccessToken` so it does not
  // accidentally appear in downstream loggers (e.g. morgan, pino-http).
  function targetToken(req) {
    const headerValue = req.headers['x-sync-target-token'];
    if (typeof headerValue === 'string' && headerValue.trim().length > 0) {
      return headerValue.trim();
    }
    const auth = req.headers?.authorization || req.headers?.Authorization;
    if (typeof auth === 'string') {
      const trimmed = auth.trim();
      // Pattern: `Bearer sync:<token>` distinguishes target-session tokens
      // from full user JWTs so the bearer middleware can keep ignoring them.
      const match = /^Bearer\s+sync:(.+)$/i.exec(trimmed);
      if (match && match[1]) return match[1].trim();
    }
    if (typeof req.body?.targetAccessToken === 'string' && req.body.targetAccessToken.length > 0) {
      return req.body.targetAccessToken;
    }
    if (typeof req.query?.targetAccessToken === 'string' && req.query.targetAccessToken.length > 0) {
      const value = req.query.targetAccessToken;
      // Strip the legacy query param from the request to keep it out of
      // downstream loggers (deprecation path — clients should migrate to the
      // header).
      try { delete req.query.targetAccessToken; } catch { /* req.query may be a frozen proxy */ }
      return value;
    }
    return null;
  }

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

  router.post(
    '/sync/create-session',
    createLimit,
    dbGuard,
    typeof optionalAuth === 'function' ? optionalAuth : (_req, _res, next) => next(),
    validateBody([
      { field: 'targetEphemeralPubKey', type: 'string' },
      { field: 'sessionCode', type: 'string', required: false },
      { field: 'origin', type: 'string', required: false },
      { field: 'version', type: 'string', required: false },
      { field: 'targetDevice', type: 'object', required: false },
    ]),
    async (req, res, next) => {
      try {
        const result = await deviceSyncService.createSession({
          ...(req.body || {}),
          sourceUserId: req.user?.id || null,
        });
        return res.status(201).json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  router.get('/sync/sessions/:sessionId', dbGuard, async (req, res, next) => {
    try {
      const result = await deviceSyncService.getSessionForTarget({
        sessionId: req.params.sessionId,
        targetAccessToken: targetToken(req),
      });
      return res.json({ success: true, session: result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post(
    '/sync/dh-submit',
    dbGuard,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'targetAccessToken', type: 'string' },
      { field: 'sourceIdentityPubKey', type: 'string' },
      { field: 'sourceDevice', type: 'object', required: false },
    ]),
    async (req, res, next) => {
      try {
        const session = await deviceSyncService.submitSourceIdentity({
          sessionId: req.body.sessionId,
          targetAccessToken: req.body.targetAccessToken,
          sourceIdentityPubKey: req.body.sourceIdentityPubKey,
          sourceDevice: req.body.sourceDevice || {},
        });
        return res.json({ success: true, session });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  router.get('/sync/dh-session/:sessionId', dbGuard, async (req, res, next) => {
    try {
      const session = await deviceSyncService.getDhSession({
        sessionId: req.params.sessionId,
        targetAccessToken: targetToken(req),
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.get('/sync/sessions/:sessionId/chunks', dbGuard, async (req, res, next) => {
    try {
      const result = await deviceSyncService.listChunksForTarget({
        sessionId: req.params.sessionId,
        targetAccessToken: targetToken(req),
      });
      return res.json({ success: true, ...result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post(
    '/sync/attach-source',
    attachLimit,
    dbGuard,
    requireAuth,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'sourceEphemeralPubKey', type: 'string' },
      { field: 'sourceDevice', type: 'object', required: false },
    ]),
    async (req, res, next) => {
      try {
        const session = await deviceSyncService.attachSource({
          sessionId: req.body.sessionId,
          sourceEphemeralPubKey: req.body.sourceEphemeralPubKey,
          sourceUserId: req.user.id,
          sourceDevice: req.body.sourceDevice || {},
        });
        return res.json({ success: true, session });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Target uploads the device IK public key. No private keys.
  router.post(
    '/sync/dh-target-identity',
    dbGuard,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'targetAccessToken', type: 'string' },
      { field: 'targetDeviceIdentityPubX25519', type: 'string' },
      { field: 'targetDeviceIdentityPubEd25519', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const session = await deviceSyncService.submitTargetDeviceIdentity({
          sessionId: req.body.sessionId,
          targetAccessToken: req.body.targetAccessToken,
          pubX25519: req.body.targetDeviceIdentityPubX25519,
          pubEd25519: req.body.targetDeviceIdentityPubEd25519,
        });
        return res.json({ success: true, session });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Source uploads the authorization signature over target IK.
  router.post(
    '/sync/dh-auth-sig',
    dbGuard,
    requireAuth,
    validateBody([
      { field: 'sessionId', type: 'string' },
      { field: 'deviceAuthorizationSignature', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const session = await deviceSyncService.submitDeviceAuthorization({
          sessionId: req.body.sessionId,
          userId: req.user.id,
          deviceAuthorizationSignature: req.body.deviceAuthorizationSignature,
        });
        return res.json({ success: true, session });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  router.post('/sync/confirm-target', dbGuard, async (req, res, next) => {
    try {
      const session = await deviceSyncService.confirmSession({
        sessionId: req.body?.sessionId,
        actor: 'target',
        targetAccessToken: targetToken(req),
        targetDevice: req.body?.targetDevice || {},
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/confirm-source', dbGuard, requireAuth, async (req, res, next) => {
    try {
      const session = await deviceSyncService.confirmSession({
        sessionId: req.body?.sessionId,
        actor: 'source',
        userId: req.user.id,
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/transfer-chunk', dbGuard, requireAuth, async (req, res, next) => {
    try {
      const session = await deviceSyncService.transferChunk({
        sessionId: req.body?.sessionId,
        userId: req.user.id,
        chunk: req.body?.chunk,
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/dh-transfer-chunk', dbGuard, async (req, res, next) => {
    try {
      const session = await deviceSyncService.transferDhChunk({
        sessionId: req.body?.sessionId,
        targetAccessToken: targetToken(req),
        chunk: req.body?.chunk,
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/complete-source', dbGuard, requireAuth, async (req, res, next) => {
    try {
      const result = await deviceSyncService.complete({
        sessionId: req.body?.sessionId,
        actor: 'source',
        userId: req.user.id,
      });
      return res.json({ success: true, ...result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/complete-target', dbGuard, async (req, res, next) => {
    try {
        const result = await deviceSyncService.complete({
          sessionId: req.body?.sessionId,
          actor: 'target',
          targetAccessToken: targetToken(req),
          targetDevice: req.body?.targetDevice || {},
          requestMetadata: requestMetadata(req),
        });
      return res.json({ success: true, ...result });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/cancel-source', dbGuard, requireAuth, async (req, res, next) => {
    try {
      const session = await deviceSyncService.cancel({
        sessionId: req.body?.sessionId,
        userId: req.user.id,
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  router.post('/sync/cancel-target', dbGuard, async (req, res, next) => {
    try {
      const session = await deviceSyncService.cancel({
        sessionId: req.body?.sessionId,
        targetAccessToken: targetToken(req),
      });
      return res.json({ success: true, session });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  return router;
}

module.exports = { createSyncRouter };
