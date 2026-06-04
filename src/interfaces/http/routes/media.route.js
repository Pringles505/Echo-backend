/**
 * @module interfaces/http/routes/media
 *
 * Encrypted media blob store for message attachments (video, etc.).
 *
 * Blobs are opaque ciphertext: the client encrypts the file with a per-message
 * key that NEVER reaches the server (it rides inside the E2EE message payload),
 * uploads the resulting container here, and the recipient downloads + decrypts
 * locally. The server only ever sees and stores bytes it cannot read.
 *
 *   POST /media      → store a ciphertext blob, returns { mediaId }
 *   GET  /media/:id  → stream the ciphertext blob back
 *
 * Access control (v1): a valid access token + an unguessable id. The ciphertext
 * is useless without the per-message key regardless. A per-conversation /
 * group membership check keyed off the referencing message is a planned
 * follow-up.
 */

const express = require('express');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { MEDIA_MAX_SIZE } = require('../../../shared/constants');

/**
 * @param {object} deps
 * @param {import('express').RequestHandler} deps.requireAuth
 * @param {{ saveMediaBlob: function, openMediaBlobStream: function }} deps.mediaStorage
 * @param {import('express').RequestHandler} [deps.mediaUploadLimiter]
 * @param {number} [deps.maxSize]
 * @returns {import('express').Router}
 */
function createMediaRouter(deps = {}) {
  const { requireAuth, mediaStorage } = deps;
  if (typeof requireAuth !== 'function') throw new Error('createMediaRouter requires requireAuth');
  if (!mediaStorage || typeof mediaStorage.saveMediaBlob !== 'function') {
    throw new Error('createMediaRouter requires mediaStorage');
  }

  const maxSize = Number.isFinite(deps.maxSize) ? deps.maxSize : MEDIA_MAX_SIZE;
  const uploadLimiter =
    typeof deps.mediaUploadLimiter === 'function'
      ? deps.mediaUploadLimiter
      : (_req, _res, next) => next();

  // Parse the body as a raw Buffer regardless of Content-Type, capped at
  // maxSize. An oversized body makes express.raw raise `entity.too.large` —
  // which it hands to `next(err)`, bypassing the route handler — so we wrap it
  // and translate that to a clean 413 inline.
  const rawBody = express.raw({ type: () => true, limit: maxSize });
  const rawBodyGuarded = (req, res, next) => {
    rawBody(req, res, (err) => {
      if (err) {
        if (err.type === 'entity.too.large' || err.status === 413 || err.statusCode === 413) {
          return sendHttpError(
            res,
            413,
            `Media exceeds max size of ${maxSize} bytes`,
            'media_too_large'
          );
        }
        return next(err);
      }
      return next();
    });
  };

  const router = express.Router();

  router.post('/media', requireAuth, uploadLimiter, rawBodyGuarded, async (req, res, next) => {
    try {
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return sendHttpError(res, 400, 'Media body must be non-empty binary', 'invalid_media');
      }
      const mediaId = await mediaStorage.saveMediaBlob(req.body);
      return res.json({ success: true, mediaId });
    } catch (err) {
      if (err?.status) return sendHttpError(res, err.status, err.message, err.code, err.details);
      return next(err);
    }
  });

  router.get('/media/:id', requireAuth, async (req, res, next) => {
    try {
      const opened = await mediaStorage.openMediaBlobStream(req.params.id);
      if (!opened) return sendHttpError(res, 404, 'Media not found', 'media_not_found');
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', String(opened.size));
      res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
      opened.stream.on('error', () => {
        if (!res.headersSent) sendHttpError(res, 500, 'Failed to read media', 'media_read_error');
        else res.destroy();
      });
      return opened.stream.pipe(res);
    } catch (err) {
      if (err?.status) return sendHttpError(res, err.status, err.message, err.code, err.details);
      return next(err);
    }
  });

  return router;
}

module.exports = { createMediaRouter };
