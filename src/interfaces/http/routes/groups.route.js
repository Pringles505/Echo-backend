/**
 * @module interfaces/http/routes/groups
 * Group messaging and MLS REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} CreateGroupRequest
 * @property {string} groupName - Name of the group
 * @property {Array<string>} memberIds - User IDs to add as members
 */

/**
 * @typedef {object} GroupResponse
 * @property {boolean} success
 * @property {string} [groupId] - Group ID if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} GroupMessageRequest
 * @property {string} groupId - Group ID
 * @property {string} payload - Encrypted message
 * @property {number} messageNumber - Message sequence number
 */

/**
 * @typedef {object} GroupsListResponse
 * @property {boolean} success
 * @property {Array} [groups] - User's groups list
 * @property {string} [error] - Error message if failed
 */

const groupsRouter = express.Router();

/**
 * @openapi
 * /groups/create:
 *   post:
 *     tags:
 *       - Groups
 *     summary: Create a new group
 *     description: Create a new group chat with specified members
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateGroupRequest'
 *     responses:
 *       200:
 *         description: Group created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GroupResponse'
 *       400:
 *         description: Invalid request
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
groupsRouter.post('/groups/create', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /groups/list:
 *   get:
 *     tags:
 *       - Groups
 *     summary: List user groups
 *     description: Get list of groups the authenticated user is member of
 *     responses:
 *       200:
 *         description: Groups list
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GroupsListResponse'
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
groupsRouter.get('/groups/list', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /groups/{groupId}:
 *   get:
 *     tags:
 *       - Groups
 *     summary: Get group details
 *     description: Fetch group information and messages
 *     parameters:
 *       - in: path
 *         name: groupId
 *         required: true
 *         schema:
 *           type: string
 *         description: Group ID
 *     responses:
 *       200:
 *         description: Group details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 group:
 *                   type: object
 *       404:
 *         description: Group not found
 *       500:
 *         description: Server error
 */
groupsRouter.get('/groups/:groupId', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /groups/{groupId}/add-member:
 *   post:
 *     tags:
 *       - Groups
 *     summary: Add member to group
 *     description: Add a user to an existing group
 *     parameters:
 *       - in: path
 *         name: groupId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Member added
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GroupResponse'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Group not found
 *       500:
 *         description: Server error
 */
groupsRouter.post('/groups/:groupId/add-member', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /groups/{groupId}/remove-member:
 *   post:
 *     tags:
 *       - Groups
 *     summary: Remove member from group
 *     description: Remove a user from a group
 *     parameters:
 *       - in: path
 *         name: groupId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *     responses:
 *       200:
 *         description: Member removed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/GroupResponse'
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Group not found
 *       500:
 *         description: Server error
 */
groupsRouter.post('/groups/:groupId/remove-member', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { groupsRouter };
