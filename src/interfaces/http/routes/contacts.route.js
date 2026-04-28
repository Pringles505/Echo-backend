/**
 * @module interfaces/http/routes/contacts
 * Friend and contact management REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} FriendRequest
 * @property {string} friendId - User ID to add/remove
 */

/**
 * @typedef {object} ContactResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if failed
 */

const contactsRouter = express.Router();

/**
 * @openapi
 * /contacts/add-friend:
 *   post:
 *     tags:
 *       - Contacts
 *     summary: Add a friend
 *     description: Add a user to your friends list
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/FriendRequest'
 *     responses:
 *       200:
 *         description: Friend added
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ContactResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
contactsRouter.post('/contacts/add-friend', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /contacts/remove-friend:
 *   post:
 *     tags:
 *       - Contacts
 *     summary: Remove a friend
 *     description: Remove a user from your friends list
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/FriendRequest'
 *     responses:
 *       200:
 *         description: Friend removed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ContactResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
contactsRouter.post('/contacts/remove-friend', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { contactsRouter };
