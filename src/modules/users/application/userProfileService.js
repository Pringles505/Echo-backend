const {
  BadRequestError,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');

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
    // Exact username match. Kept for backward compatibility with the
    // `searchUser` socket handler.
    async searchUser({ searchTerm }) {
      if (typeof searchTerm !== 'string' || searchTerm.length === 0) {
        throw new BadRequestError('searchTerm is required', 'validation_error');
      }
      const user = await User.findOne({ username: searchTerm });
      if (!user) throw new NotFoundError('User not found', 'user_not_found');
      return { id: user.id, username: user.username };
    },

    async searchUsers({ searchTerm, limit = 20, excludeUserId = null }) {
      if (typeof searchTerm !== 'string' || searchTerm.trim().length === 0) {
        throw new BadRequestError('searchTerm is required', 'validation_error');
      }
      const term = searchTerm.trim();
      // Escape regex metacharacters so usernames with `.` or `+` are treated as literals.
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const filter = { username: { $regex: `^${escaped}`, $options: 'i' } };
      if (excludeUserId) filter.id = { $ne: excludeUserId };
      const docs = await User.find(filter)
        .limit(Math.max(1, Math.min(50, Number(limit) || 20)))
        .lean();
      const users = docs.map((u) => ({
        id: u.id,
        username: u.username,
        aboutme: u.aboutme || '',
        profilePicture: u.profilePicture || '',
        banner: u.banner || '',
      }));
      return { users };
    },


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

    async updateProfile({ userId, changes }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      const safe = changes && typeof changes === 'object' ? changes : {};
      const { username, aboutme, profilePicture, oldPassword, newPassword } = safe;

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

    // Re-verifies the password before deletion.
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

    listOnlineUserIds() {
      if (!notifier || typeof notifier.listOnlineUserIds !== 'function') return [];
      const ids = notifier.listOnlineUserIds();
      return Array.isArray(ids) ? ids : [];
    },
  };
}

module.exports = { createUserProfileService };
