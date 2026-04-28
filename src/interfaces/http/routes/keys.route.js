/**
 * @module interfaces/http/routes/keys
 * Signal Protocol and OPK management REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} KeyBundleRequest
 * @property {string} targetUserId - User ID to fetch keys for
 */

/**
 * @typedef {object} KeyBundleResponse
 * @property {boolean} success
 * @property {string} [signedPreKey] - Base64 signed pre-key
 * @property {string} [signature] - Base64 signature
 * @property {Array} [oneTimePreKeys] - OPK array
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} OPKUploadRequest
 * @property {Array} oneTimePreKeys - Array of OPK objects to upload
 */

/**
 * @typedef {object} OPKResponse
 * @property {boolean} success
 * @property {number} [count] - Current OPK count
 * @property {string} [error] - Error message if failed
 */

const keysRouter = express.Router();

/**
 * @openapi
 * /keys/signed-prekey:
 *   post:
 *     tags:
 *       - Keys
 *     summary: Get signed pre-key for user
 *     description: Fetch the current signed pre-key for a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/KeyBundleRequest'
 *     responses:
 *       200:
 *         description: Signed pre-key
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 signedPreKey:
 *                   type: string
 *                 signature:
 *                   type: string
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
keysRouter.post('/keys/signed-prekey', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /keys/identity/x25519:
 *   post:
 *     tags:
 *       - Keys
 *     summary: Get X25519 identity key
 *     description: Fetch X25519 identity public key for a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/KeyBundleRequest'
 *     responses:
 *       200:
 *         description: Identity key
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 publicIdentityKeyX25519:
 *                   type: string
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
keysRouter.post('/keys/identity/x25519', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /keys/identity/ed25519:
 *   post:
 *     tags:
 *       - Keys
 *     summary: Get Ed25519 identity key
 *     description: Fetch Ed25519 identity public key for a user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/KeyBundleRequest'
 *     responses:
 *       200:
 *         description: Identity key
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 publicIdentityKeyEd25519:
 *                   type: string
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
keysRouter.post('/keys/identity/ed25519', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /keys/bundle:
 *   post:
 *     tags:
 *       - Keys
 *     summary: Get pre-key bundle for user
 *     description: Fetch complete pre-key bundle including signed pre-key and one-time pre-keys
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/KeyBundleRequest'
 *     responses:
 *       200:
 *         description: Pre-key bundle
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/KeyBundleResponse'
 *       404:
 *         description: User not found
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Server error
 */
keysRouter.post('/keys/bundle', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /keys/opk/upload:
 *   post:
 *     tags:
 *       - Keys
 *     summary: Upload one-time pre-keys
 *     description: Upload new one-time pre-keys to server
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/OPKUploadRequest'
 *     responses:
 *       200:
 *         description: OPKs uploaded
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/OPKResponse'
 *       400:
 *         description: Invalid request (too many OPKs)
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
keysRouter.post('/keys/opk/upload', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /keys/opk/status:
 *   get:
 *     tags:
 *       - Keys
 *     summary: Get OPK status
 *     description: Check current one-time pre-key count for authenticated user
 *     responses:
 *       200:
 *         description: OPK status
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/OPKResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
keysRouter.get('/keys/opk/status', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { keysRouter };
