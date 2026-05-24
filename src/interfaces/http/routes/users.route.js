const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const {
  createUserProfileService,
} = require('../../../modules/users/application/userProfileService');

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
        const user = await userProfileService.updateProfile({
          userId,
          changes: req.body || {},
        });
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
   *       knowledge.
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

  // Keep `notifier` referenced so the linter doesn't flag the deps param
  // as unused when no endpoint here calls it directly.
  void notifier;

  return router;
}

module.exports = { createUsersRouter };
