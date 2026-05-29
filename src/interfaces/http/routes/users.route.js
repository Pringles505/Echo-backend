/**
 * @module interfaces/http/routes/users
 * User profile and account REST endpoints.
 *
 * Mirrors the contactsAccount/presence socket handlers as functional REST
 * routes backed by `userProfileService`. Authentication is enforced by the
 * shared `requireAuth` middleware; rate limits and DB readiness are layered
 * with the same primitives as the auth router.
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const {
  createUserProfileService,
} = require('../../../modules/users/application/userProfileService');

/**
 * @param {object} deps
 * @param {object} [deps.userProfileService] - Pre-built service. When omitted,
 *   the router constructs one from `models.User`, `models.Message`, `bcrypt`,
 *   `services.saveProfilePicture`, and `notifier` so the composition root
 *   (server.js) can pass its `httpDeps` blob unchanged.
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} deps.requireAuth
 * @param {import('express').RequestHandler} [deps.searchLimiter]
 * @param {{ listOnlineUserIds: () => string[], emitToUser?: function }} [deps.notifier]
 * @param {{ User: any, Message?: any }} [deps.models]
 * @param {{ saveProfilePicture?: function }} [deps.services]
 * @param {*} [deps.bcrypt]
 * @param {{ searchLimiter?: import('express').RequestHandler }} [deps.rateLimit]
 * @returns {import('express').Router}
 */
function createUsersRouter(deps = {}) {
  const {
    mongoose,
    requireAuth,
    notifier,
    models = {},
    services = {},
    bcrypt,
    rateLimit = {},
  } = deps;

  const userProfileService = deps.userProfileService || createUserProfileService({
    User: models.User,
    Message: models.Message,
    bcrypt,
    saveProfilePicture: services.saveProfilePicture,
    saveBanner: services.saveBanner,
    notifier,
  });

  const searchLimiter = deps.searchLimiter || rateLimit.searchLimiter;
  const bannerLimiter = deps.bannerLimiter || rateLimit.bannerLimiter;

  if (!mongoose) throw new Error('createUsersRouter requires mongoose');
  if (typeof requireAuth !== 'function') {
    throw new Error('createUsersRouter requires requireAuth middleware');
  }

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const searchLimit = typeof searchLimiter === 'function'
    ? searchLimiter
    : (_req, _res, next) => next();
  const bannerLimit = typeof bannerLimiter === 'function'
    ? bannerLimiter
    : (_req, _res, next) => next();

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /users/search:
   *   post:
   *     tags: [Users]
   *     summary: Search for users by username prefix
   *     description: |
   *       Case-insensitive prefix search by username. Returns an array of full
   *       public profiles (id, username, aboutme, profilePicture, banner).
   *       Limited to 20 results, never includes the authenticated user.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/SearchUserRequest'
   *     responses:
   *       200:
   *         description: Matches (may be empty)
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 success: { type: boolean }
   *                 users:
   *                   type: array
   *                   items: { $ref: '#/components/schemas/UserProfile' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/users/search',
    requireAuth,
    dbGuard,
    searchLimit,
    validateBody([
      { field: 'searchTerm', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const { searchTerm } = req.body;
        const { users } = await userProfileService.searchUsers({
          searchTerm,
          excludeUserId: req.user?.id || null,
        });
        return res.json({ success: true, users });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /users/online:
   *   get:
   *     tags: [Users]
   *     summary: List currently online user IDs
   *     description: Snapshot of users currently connected over Socket.IO.
   *     responses:
   *       200:
   *         description: Online users snapshot
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/OnlineUsersResponse'
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   */
  router.get(
    '/users/online',
    requireAuth,
    (_req, res) => {
      const onlineUsers = userProfileService.listOnlineUserIds();
      return res.json({ success: true, onlineUsers });
    }
  );

  /**
   * @openapi
   * /users/profile/update:
   *   put:
   *     tags: [Users]
   *     summary: Update authenticated user's profile and account
   *     description: |
   *       Updates one or more of: username, aboutme, profilePicture, password.
   *       Changing the password requires both `oldPassword` and `newPassword`.
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
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.put(
    '/users/profile/update',
    requireAuth,
    dbGuard,
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        // Normalize frontend aliases -> service schema
        const body = req.body || {};
        const changes = {};
        if (typeof body.username === 'string' && body.username) changes.username = body.username;
        if (typeof body.display_name === 'string' && body.display_name)
          changes.username = body.display_name;
        if (typeof body.aboutme === 'string') changes.aboutme = body.aboutme;
        if (typeof body.bio === 'string') changes.aboutme = body.bio;
        if (typeof body.profilePicture === 'string') changes.profilePicture = body.profilePicture;
        if (typeof body.avatar_url === 'string') changes.profilePicture = body.avatar_url;
        if (typeof body.oldPassword === 'string') changes.oldPassword = body.oldPassword;
        if (typeof body.newPassword === 'string') changes.newPassword = body.newPassword;

        const user = await userProfileService.updateProfile({ userId, changes });
        // Broadcast profile updates so open UIs and notifications refresh avatars
        // Emit to each user's room so ALL of their devices receive the event,
        // not just the last socket in userSocketMap (emitToUser targets one).
        try {
          const payload = {
            userId: user.id,
            username: user.username,
            profilePicture: user.profilePicture || '',
          };
          if (
            notifier &&
            typeof notifier.listOnlineUserIds === 'function' &&
            // prefer room fanout (every device joined the parent userId room)
            typeof notifier.emitToRoom === 'function'
          ) {
            const onlineIds = notifier.listOnlineUserIds();
            for (const uid of Array.isArray(onlineIds) ? onlineIds : []) {
              notifier.emitToRoom(String(uid), 'userProfileUpdated', payload);
            }
          }
        } catch (broadcastErr) {
          // Non-fatal: HTTP response should still succeed
          console.warn('[http] Failed to broadcast userProfileUpdated:', broadcastErr);
        }
        return res.json({ success: true, user });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /users/profile/banner:
   *   put:
   *     tags: [Users]
   *     summary: Update authenticated user's profile banner
   *     description: |
   *       Uploads a base64-encoded banner image (`data:image/...`) and stores
   *       the resulting URL on the user's profile. Mirrors the profile-picture
   *       upload flow but keeps the cover banner independent.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/BannerUpdateRequest'
   *     responses:
   *       200:
   *         description: Banner updated
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/BannerUpdateResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       429: { $ref: '#/components/responses/RateLimitedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.put(
    '/users/profile/banner',
    requireAuth,
    bannerLimit,
    dbGuard,
    validateBody([
      { field: 'banner', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { banner } = req.body;
        const user = await userProfileService.updateBanner({ userId, banner });
        return res.json({ success: true, user });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /users/account/delete:
   *   delete:
   *     tags: [Users]
   *     summary: Delete authenticated user account
   *     description: |
   *       Permanently deletes the authenticated account and its messages.
   *       Requires the current password in the request body for proof of
   *       knowledge (mitigation for SEC-002).
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/DeleteAccountRequest'
   *     responses:
   *       200:
   *         description: Account deleted
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/SuccessResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.delete(
    '/users/account/delete',
    requireAuth,
    dbGuard,
    validateBody([
      { field: 'password', type: 'string' },
    ]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { password } = req.body;
        await userProfileService.deleteAccount({ userId, password });
        return res.json({ success: true });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /users/{userId}:
   *   get:
   *     tags: [Users]
   *     summary: Fetch user profile by id
   *     description: Returns the public profile (username, aboutme, profilePicture, friends) for `userId`.
   *     parameters:
   *       - in: path
   *         name: userId
   *         required: true
   *         schema:
   *           type: string
   *         description: Public user identifier (5-char nanoid).
   *     responses:
   *       200:
   *         description: User found
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/UserResponse'
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.get(
    '/users/:userId',
    requireAuth,
    dbGuard,
    async (req, res, next) => {
      try {
        const { userId } = req.params;
        const user = await userProfileService.getUserById({ userId });
        return res.json({ success: true, user });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  // notifier kept in deps signature for parity / future endpoints; reference
  // it here so linters don't flag it as unused even when not directly called.
  void notifier;

  return router;
}

module.exports = { createUsersRouter };
