/**
 * @module interfaces/http/routes/auth
 * Authentication REST endpoints
 */

const express = require('express');
const { respondSocketOnly } = require('./socketOnlyResponse');

/**
 * @typedef {object} RegisterRequest
 * @property {string} username - Account identifier
 * @property {string} password - Account password
 * @property {object} keyBundle - Signal Protocol keys
 * @property {string} [aboutme] - User bio
 * @property {string} [profilePicture] - Profile picture (base64)
 */

/**
 * @typedef {object} RegisterResponse
 * @property {boolean} success
 * @property {string} [userId] - User ID if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} LoginRequest
 * @property {string} username - Username
 * @property {string} password - Password
 */

/**
 * @typedef {object} LoginResponse
 * @property {boolean} success
 * @property {string} [token] - JWT token if successful
 * @property {string} [userId] - User ID if successful
 * @property {string} [error] - Error message if failed
 */

const authRouter = express.Router();

/**
 * @openapi
 * /auth/register:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Register a new user account
 *     description: Create a new user with Signal Protocol key bundle
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *     responses:
 *       200:
 *         description: Registration successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/RegisterResponse'
 *       400:
 *         description: Invalid request
 *       409:
 *         description: Username already taken
 *       500:
 *         description: Server error
 */
authRouter.post('/auth/register', async (req, res) => {
  return respondSocketOnly(res);
});

/**
 * @openapi
 * /auth/login:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Authenticate user and get JWT token
 *     description: Login with username and password to receive authentication token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Server error
 */
authRouter.post('/auth/login', async (req, res) => {
  return respondSocketOnly(res);
});

module.exports = { authRouter };
