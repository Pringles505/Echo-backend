/**
 * @module modules/users/application/userProfileService
 *
 * Application service for user profile and account use cases.
 * Mirrors the logic of the `searchUser`, `getUserInfo`, `updateUserInfo`,
 * `deleteAccount`, and `getOnlineUsers` socket handlers, but is framework
 * agnostic — it does not touch socket primitives directly.
 *
 * Throws domain/HTTP errors from `src/shared/errors`. The Express router
 * translates them into structured HTTP responses; socket adapters can wrap
 * the same errors into ack payloads.
 */

const {
  BadRequestError,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');

/**
 * @typedef {object} UpdateProfileChanges
 * @property {string} [username]
 * @property {string} [aboutme]
 * @property {string} [profilePicture] - Base64 data URL (`data:image/...`)
 * @property {string} [oldPassword]
 * @property {string} [newPassword]
 */

/**
 * @typedef {object} PublicUser
 * @property {string} id
 * @property {string} username
 * @property {string} [aboutme]
 * @property {string} [profilePicture]
 * @property {Array<string>} [friends]
 */

/**
 * @param {object} deps
 * @param {import('mongoose').Model} deps.User
 * @param {import('mongoose').Model} [deps.Message]
 * @param {*} deps.bcrypt - bcryptjs module
 * @param {function} [deps.saveProfilePicture] - (dataUrl, userId) => Promise<string>
 * @param {function} [deps.saveBanner] - (dataUrl, userId) => Promise<string>
 * @param {{ listOnlineUserIds: () => string[] }} [deps.notifier]
 */
function createUserProfileService({
  User,
  Message,
  bcrypt,
  saveProfilePicture,
  saveBanner,
  notifier,
} = {}) {
  if (!User) throw new Error('createUserProfileService requires User model');
  if (!bcrypt) throw new Error('createUserProfileService requires bcrypt');

  return {
    /**
     * Find a user by username.
     * @param {{ searchTerm: string }} input
     * @returns {Promise<PublicUser>}
     */
    async searchUser({ searchTerm }) {
      if (typeof searchTerm !== 'string' || searchTerm.length === 0) {
        throw new BadRequestError('searchTerm is required', 'validation_error');
      }
      const user = await User.findOne({ username: searchTerm });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');
      return { id: user.id, username: user.username };
    },

    /**
     * Fetch a public user profile by id.
     * @param {{ userId: string }} input
     * @returns {Promise<PublicUser>}
     */
    async getUserById({ userId }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      const user = await User.findOne({ id: userId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');
      return {
        id: user.id,
        username: user.username,
        aboutme: user.aboutme,
        profilePicture: user.profilePicture,
        banner: user.banner,
        friends: user.friends,
      };
    },

    /**
     * Update the authenticated user's profile/account.
     * @param {{ userId: string, changes: UpdateProfileChanges }} input
     * @returns {Promise<PublicUser>}
     */
    async updateProfile({ userId, changes }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      const safe = changes && typeof changes === 'object' ? changes : {};
      const { username, aboutme, profilePicture, oldPassword, newPassword } = safe;

      // Password change preconditions are validated up front so callers get
      // a clean 400 before any DB work happens.
      if (newPassword && !oldPassword) {
        throw new BadRequestError(
          'oldPassword is required when newPassword is provided',
          'old_password_required'
        );
      }

      const user = await User.findOne({ id: userId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      if (typeof username === 'string' && username.length > 0) {
        user.username = username;
      }
      if (typeof aboutme === 'string') {
        user.aboutme = aboutme;
      }
      if (typeof profilePicture === 'string' && profilePicture.startsWith('data:image/')) {
        if (typeof saveProfilePicture !== 'function') {
          throw new BadRequestError(
            'Profile picture upload is not configured',
            'profile_picture_unsupported'
          );
        }
        const url = await saveProfilePicture(profilePicture, userId);
        user.profilePicture = url;
      }

      if (oldPassword && newPassword) {
        const isMatch = await bcrypt.compare(oldPassword, user.hashedPassword);
        if (!isMatch) {
          throw new UnauthorizedError('Old password is incorrect', 'invalid_credentials');
        }
        user.hashedPassword = await bcrypt.hash(newPassword, 10);
      }

      try {
        await user.save();
      } catch (err) {
        if (err?.code === 11000 && err?.keyPattern?.username) {
          throw new ConflictError('Username already taken', 'username_conflict');
        }
        throw err;
      }

      return {
        id: user.id,
        username: user.username,
        aboutme: user.aboutme,
        profilePicture: user.profilePicture,
        banner: user.banner,
      };
    },

    /**
     * Update the authenticated user's banner image.
     * Accepts a base64 data URL and delegates to the injected `saveBanner`
     * helper which writes a file under `/uploads/banner-...`.
     * @param {{ userId: string, banner: string }} input
     * @returns {Promise<{ id: string, username: string, banner: string }>}
     */
    async updateBanner({ userId, banner }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (typeof banner !== 'string' || !banner.startsWith('data:image/')) {
        throw new BadRequestError(
          'banner must be a base64 data URL (data:image/...)',
          'validation_error'
        );
      }
      if (typeof saveBanner !== 'function') {
        throw new BadRequestError(
          'Banner upload is not configured',
          'banner_unsupported'
        );
      }

      const user = await User.findOne({ id: userId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      const url = await saveBanner(banner, userId);
      user.banner = url;
      await user.save();

      return {
        id: user.id,
        username: user.username,
        banner: user.banner,
      };
    },

    /**
     * Permanently delete an account after re-verifying the password
     * (mitigation for SEC-002: socket-only delete had no proof-of-knowledge).
     * @param {{ userId: string, password: string }} input
     * @returns {Promise<{ deleted: true }>}
     */
    async deleteAccount({ userId, password }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (typeof password !== 'string' || password.length === 0) {
        throw new BadRequestError('password is required', 'validation_error');
      }

      const user = await User.findOne({ id: userId });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');

      const isMatch = await bcrypt.compare(password, user.hashedPassword);
      if (!isMatch) {
        throw new UnauthorizedError('Password is incorrect', 'invalid_credentials');
      }

      await User.deleteOne({ id: userId });
      if (Message && typeof Message.deleteMany === 'function') {
        await Message.deleteMany({
          $or: [{ userId }, { targetUserId: userId }],
        });
      }
      return { deleted: true };
    },

    /**
     * Synchronous list of currently online user IDs as known to the notifier.
     * @returns {Array<string>}
     */
    listOnlineUserIds() {
      if (!notifier || typeof notifier.listOnlineUserIds !== 'function') return [];
      const ids = notifier.listOnlineUserIds();
      return Array.isArray(ids) ? ids : [];
    },
  };
}

module.exports = { createUserProfileService };
