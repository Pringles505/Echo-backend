const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');

function createDevicesRouter({ deviceManagementService, mongoose, requireAuth } = {}) {
  if (!deviceManagementService) throw new Error('createDevicesRouter requires deviceManagementService');
  if (!mongoose) throw new Error('createDevicesRouter requires mongoose');
  if (typeof requireAuth !== 'function') throw new Error('createDevicesRouter requires requireAuth');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function requestMetadata(req) {
    return {
      ipAddress: req.ip || req.socket?.remoteAddress || null,
      userAgent: req.headers['user-agent'] || null,
    };
  }

  function handleError(res, next, err) {
    if (err?.status) return sendHttpError(res, err.status, err.message, err.code, err.details);
    return next(err);
  }

  // List linked devices for a user (returns public metadata, no keys)
  router.get('/users/:userId/devices', requireAuth, dbGuard, async (req, res, next) => {
    try {
      if (String(req.user.id) !== String(req.params.userId)) {
        return sendHttpError(res, 403, 'Cannot list devices for another user', 'device_forbidden');
      }
      const devices = await deviceManagementService.listDevices({ parentUserId: req.params.userId });
      return res.json({ success: true, devices });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  // Get full public key bundles for message fanout (consumes one OPK per device)
  router.get('/users/:userId/devices/bundles', requireAuth, dbGuard, async (req, res, next) => {
    try {
      const bundles = await deviceManagementService.getDeviceBundles({ parentUserId: req.params.userId });
      return res.json({ success: true, bundles });
    } catch (err) {
      return handleError(res, next, err);
    }
  });

  // Upload or replace a device's public key bundle after provisioning
  router.post(
    '/devices/:deviceId/keys',
    requireAuth,
    dbGuard,
    async (req, res, next) => {
      try {
        const result = await deviceManagementService.registerDeviceKeys({
          deviceId: req.params.deviceId,
          requesterId: req.user.id,
          keyBundle: req.body || {},
          requestMetadata: requestMetadata(req),
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  // Revoke (unlink) a device — only parent user can revoke
  router.post(
    '/devices/:deviceId/revoke',
    requireAuth,
    dbGuard,
    async (req, res, next) => {
      try {
        const result = await deviceManagementService.revokeDevice({
          deviceId: req.params.deviceId,
          requesterId: req.user.id,
        });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createDevicesRouter };
