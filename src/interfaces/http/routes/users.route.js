/**
 * @module interfaces/http/routes/users
 * User profile and contact management REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} SearchUserRequest
 * @property {string} searchTerm - Username to search for
 */

/**
 * @typedef {object} UserProfile
 * @property {string} id - User ID
 * @property {string} username - Username
 * @property {string} [aboutme] - User bio
 * @property {string} [profilePicture] - Profile picture URL
 */

/**
 * @typedef {object} UserResponse
 * @property {boolean} success
 * @property {UserProfile} [user] - User info if found
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} UpdateUserRequest
 * @property {string} [username] - New username
 * @property {string} [aboutme] - New bio
 * @property {string} [profilePicture] - New profile picture (base64 data URL)
 * @property {string} [oldPassword] - Old password for verification
 * @property {string} [newPassword] - New password (requires oldPassword)
 */

/**
 * @typedef {object} OnlineUsersResponse
 * @property {boolean} success
 * @property {Array<string>} [onlineUsers] - List of online user IDs
 * @property {string} [error] - Error message if failed
 */

const usersRouter = express.Router();

/**
 * @openapi
 * /users/search:
 *   post:
 *     tags:
 *       - Users
 *     summary: Search for a user by username
 *     description: Find a user by username
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SearchUserRequest'
 *     responses:
 *       200:
 *         description: Search result
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserResponse'
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
usersRouter.post('/users/search', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /users/{userId}:
 *   get:
 *     tags:
 *       - Users
 *     summary: Get user information
 *     description: Fetch user profile information by user ID
 *     parameters:
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: User info
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserResponse'
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
usersRouter.get('/users/:userId', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /users/profile/update:
 *   put:
 *     tags:
 *       - Users
 *     summary: Update authenticated user profile
 *     description: Update current user's profile information and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateUserRequest'
 *     responses:
 *       200:
 *         description: Profile updated
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/UserResponse'
 *       401:
 *         description: Unauthorized or invalid password
 *       500:
 *         description: Server error
 */
usersRouter.put('/users/profile/update', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /users/online:
 *   get:
 *     tags:
 *       - Users
 *     summary: Get list of online users
 *     description: Retrieve list of currently online users
 *     responses:
 *       200:
 *         description: Online users list
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/OnlineUsersResponse'
 *       500:
 *         description: Server error
 */
usersRouter.get('/users/online', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /users/account/delete:
 *   delete:
 *     tags:
 *       - Users
 *     summary: Delete user account
 *     description: Permanently delete the authenticated user account
 *     responses:
 *       200:
 *         description: Account deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
usersRouter.delete('/users/account/delete', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { usersRouter };
