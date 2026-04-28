/**
 * @module interfaces/http/routes/messages
 * Direct and group messaging REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} MessageRequest
 * @property {string} targetUserId - Recipient user ID
 * @property {string} payload - Encrypted message
 * @property {number} messageNumber - Sequence number
 */

/**
 * @typedef {object} MessageResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} MessagesListResponse
 * @property {boolean} success
 * @property {Array} [messages] - Array of message objects
 * @property {string} [error] - Error message if failed
 */

const messagesRouter = express.Router();

/**
 * @openapi
 * /messages/check:
 *   post:
 *     tags:
 *       - Messages
 *     summary: Check if messages exist with user
 *     description: Check if any messages exist in conversation with a target user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               targetUserId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Check result
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 exists:
 *                   type: boolean
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
messagesRouter.post('/messages/check', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /messages/latest-number:
 *   post:
 *     tags:
 *       - Messages
 *     summary: Get latest message number
 *     description: Get the last accepted message number in a conversation
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               targetUserId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Latest message number
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 messageNumber:
 *                   type: number
 *       500:
 *         description: Server error
 */
messagesRouter.post('/messages/latest-number', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /messages/mark-seen:
 *   post:
 *     tags:
 *       - Messages
 *     summary: Mark messages as seen
 *     description: Mark messages from a user as read
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               targetUserId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Messages marked as seen
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Server error
 */
messagesRouter.post('/messages/mark-seen', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { messagesRouter };
