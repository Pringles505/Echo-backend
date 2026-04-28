/**
 * @module interfaces/http/routes/calls
 * Voice and video calling REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} InitiateCallRequest
 * @property {string} targetUserId - Recipient user ID
 * @property {string} callId - Unique call identifier
 */

/**
 * @typedef {object} CallResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} CallStateRequest
 * @property {string} callId - Call ID
 * @property {boolean} isEnabled - Media enabled (audio/video)
 */

const callsRouter = express.Router();

/**
 * @openapi
 * /calls/initiate:
 *   post:
 *     tags:
 *       - Calls
 *     summary: Initiate a call
 *     description: Start a voice/video call with another user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/InitiateCallRequest'
 *     responses:
 *       200:
 *         description: Call initiated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/CallResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
callsRouter.post('/calls/initiate', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /calls/accept:
 *   post:
 *     tags:
 *       - Calls
 *     summary: Accept an incoming call
 *     description: Accept a call from another user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               callId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Call accepted
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/CallResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
callsRouter.post('/calls/accept', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /calls/decline:
 *   post:
 *     tags:
 *       - Calls
 *     summary: Decline an incoming call
 *     description: Reject a call from another user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               callId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Call declined
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/CallResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
callsRouter.post('/calls/decline', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /calls/end:
 *   post:
 *     tags:
 *       - Calls
 *     summary: End an active call
 *     description: Terminate an ongoing call
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               callId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Call ended
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/CallResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
callsRouter.post('/calls/end', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /calls/media-state:
 *   post:
 *     tags:
 *       - Calls
 *     summary: Update media state
 *     description: Update audio or video state during a call
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               callId:
 *                 type: string
 *               mediaType:
 *                 type: string
 *                 enum: [audio, video]
 *               isEnabled:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Media state updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/CallResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
callsRouter.post('/calls/media-state', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { callsRouter };
