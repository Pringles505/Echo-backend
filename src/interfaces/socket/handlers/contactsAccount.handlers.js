/**
 * Socket event handlers for user contacts, account management, and profile updates.
 * Implements user search, friend management, and profile information updates.
 * @module interfaces/socket/handlers/contactsAccount
 */

/**
 * @typedef {object} SearchUserPayload
 * @property {string} searchTerm - Username to search for
 */

/**
 * @typedef {object} SearchUserAckResponse
 * @property {boolean} success
 * @property {object} [user] - User info if found
 * @property {string} [user.id] - User ID
 * @property {string} [user.username] - Username
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} UpdateUserInfoPayload
 * @property {string} [username] - New username
 * @property {string} [aboutme] - New bio/about text
 * @property {string} [profilePicture] - Profile picture as base64 data URL
 * @property {string} [oldPassword] - Current password for verification
 * @property {string} [newPassword] - New password (requires oldPassword)
 */

/**
 * @typedef {object} UpdateUserInfoAckResponse
 * @property {boolean} success
 * @property {object} [user] - Updated user info if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * @typedef {object} GetUserInfoPayload
 * @property {string} userId - User ID to fetch info for
 */

/**
 * @typedef {object} AddFriendPayload
 * @property {string} friendId - User ID to add as friend
 */

/**
 * @typedef {object} RemoveFriendPayload
 * @property {string} friendId - User ID to remove from friends
 */

/**
 * Registers Socket.IO handlers for account and contact management.
 * Enables user search, profile updates, password changes, and friend management.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
 * @param {import('mongoose').Model} deps.User - User model
 * @param {import('mongoose').Model} deps.Message - Message model
 * @param {*} deps.bcrypt - Bcryptjs module for password operations
 * @param {function} deps.saveProfilePicture - Function to save profile picture
 */
const { queryUsersByUsername } = require('../../../modules/users/application/userProfileService');

function registerContactsAccountSocketHandlers({ socket, io, userSocketMap, User, Message, bcrypt, saveProfilePicture }) {
  /**
   * 'searchUser' event - Search for a user by username.
   * @event searchUser
   * @type {SearchUserPayload}
   * @param {SearchUserAckResponse} callback - Ack callback
   */
  socket.on('searchUser', async (data, callback) => {
    const searchTerm = typeof data?.searchTerm === 'string' ? data.searchTerm.trim() : '';
    if (!searchTerm) {
      return callback({ success: false, error: 'searchTerm is required' });
    }
    try {
      const docs = await queryUsersByUsername(User, { searchTerm, limit: 1 });
      if (docs.length === 0) return callback({ success: false, error: 'User not found' });
      const user = docs[0];
      callback({ success: true, user: { id: user.id, username: user.username } });
    } catch (error) {
      console.error('Error searching user:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  /**
   * 'updateUserInfo' event - Update authenticated user's profile and account.
   * Handles username, bio, profile picture, and password changes.
   * @event updateUserInfo
   * @type {UpdateUserInfoPayload}
   * @param {UpdateUserInfoAckResponse} callback - Ack callback
   */
  socket.on('updateUserInfo', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });
    // Accept both legacy and aliased fields from various clients
    const username = typeof data?.username === 'string' && data.username
      ? data.username
      : (typeof data?.display_name === 'string' && data.display_name) || undefined;
    const aboutme = typeof data?.aboutme === 'string' ? data.aboutme
      : (typeof data?.bio === 'string' ? data.bio : undefined);
    const profilePicture = typeof data?.profilePicture === 'string' ? data.profilePicture
      : (typeof data?.avatar_url === 'string' ? data.avatar_url : undefined);
    const oldPassword = data?.oldPassword;
    const newPassword = data?.newPassword;
    try {
      const user = await User.findOne({ id: authedUserId });
      if (!user) return callback?.({ success: false, error: 'User not found' });

      if (typeof username === 'string' && username.length > 0) user.username = username;
      if (typeof aboutme === 'string') user.aboutme = aboutme;

      if (typeof profilePicture === 'string' && profilePicture.startsWith('data:image/')) {
        const url = await saveProfilePicture(profilePicture, authedUserId);
        user.profilePicture = url;
      }

      if (oldPassword && newPassword) {
        const isMatch = await bcrypt.compare(oldPassword, user.hashedPassword);
        if (!isMatch) return callback?.({ success: false, error: 'Old password is incorrect' });
        user.hashedPassword = await bcrypt.hash(newPassword, 10);
      }

      await user.save();

      // Broadcast updated profile to all relevant listeners so open UIs refresh
      // and notifications use the latest avatar. Emit to:
      // - this user's room (all devices)
      // - everyone else online (clients will ignore if not relevant)
      try {
        const payload = {
          userId: user.id,
          username: user.username,
          profilePicture: user.profilePicture || '',
        };
        io.to(user.id).emit('userProfileUpdated', payload);
        socket.broadcast.emit('userProfileUpdated', payload);
      } catch (broadcastErr) {
        console.warn('[socket] Failed to broadcast userProfileUpdated:', broadcastErr);
      }

      callback?.({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          aboutme: user.aboutme,
          profilePicture: user.profilePicture,
        },
      });
    } catch (err) {
      if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
        return callback?.({ success: false, error: 'Username already taken' });
      }
      console.error('Error updating user info:', err);
      callback?.({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('getUserInfo', async ({ userId }, cb) => {
    // Defense-in-depth: the global socket middleware already blocks
    // unauthenticated events, but mirror the explicit guard used by
    // updateUserInfo/deleteAccount so this handler is safe in isolation.
    if (!socket.user?.id) return cb?.({ success: false, error: 'unauthorized' });
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        cb({
          success: true,
          // Public profile fields only. The target's `friends` list is private
          // and was previously leaked to any authenticated caller — do not return it.
          user: {
            id: user.id,
            username: user.username,
            aboutme: user.aboutme,
            profilePicture: user.profilePicture,
          },
        });
      } else {
        cb({ success: false, error: 'User not found' });
      }
    } catch (err) {
      console.error('Error fetching user info:', err);
      cb({ success: false, error: 'Internal server error' });
    }
  });

  socket.on('deleteAccount', async (_data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    try {
      await User.deleteOne({ id: authedUserId });
      await Message.deleteMany({ $or: [{ userId: authedUserId }, { targetUserId: authedUserId }] });
      callback?.({ success: true });
    } catch (err) {
      console.error('Error deleting account:', err);
      callback?.({ success: false, error: 'Failed to delete account' });
    }
  });

  socket.on('addFriend', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const { targetUserId } = data;
    try {
      const [user, targetUser] = await Promise.all([
        User.findOne({ id: authedUserId }),
        User.findOne({ id: targetUserId }),
      ]);

      if (!user || !targetUser) return callback({ success: false, error: 'User(s) not found' });
      if (user.friends.includes(targetUserId)) return callback({ success: false, error: 'Already friends' });

      user.friends.push(targetUserId);
      await user.save();

      const userSocketId = userSocketMap[authedUserId];
      const targetSocketId = userSocketMap[targetUserId];
      if (userSocketId) {
        io.to(userSocketId).emit('friendAdded', {
          friendId: targetUserId,
          friendUsername: targetUser.username,
        });
      }
      if (targetSocketId) {
        io.to(targetSocketId).emit('friendAdded', {
          friendId: authedUserId,
          friendUsername: user.username,
        });
      }

      callback({ success: true });
    } catch (err) {
      console.error('Error adding friend:', err);
      callback({ success: false, error: 'Failed to add friend' });
    }
  });

  socket.on('removeFriend', async (data, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return callback?.({ success: false, error: 'unauthorized' });

    const { targetUserId } = data;
    try {
      const [user, targetUser] = await Promise.all([
        User.findOne({ id: authedUserId }),
        User.findOne({ id: targetUserId }),
      ]);

      if (!user || !targetUser) return callback({ success: false, error: 'User(s) not found' });

      const userFriendIndex = user.friends.indexOf(targetUserId);
      const targetFriendIndex = targetUser.friends.indexOf(authedUserId);
      if (userFriendIndex === -1 || targetFriendIndex === -1) return callback({ success: false, error: 'Not friends' });

      user.friends.splice(userFriendIndex, 1);
      targetUser.friends.splice(targetFriendIndex, 1);
      await Promise.all([user.save(), targetUser.save()]);

      const userSocketId = userSocketMap[authedUserId];
      const targetSocketId = userSocketMap[targetUserId];
      if (userSocketId) io.to(userSocketId).emit('friendRemoved', { friendId: targetUserId });
      if (targetSocketId) io.to(targetSocketId).emit('friendRemoved', { friendId: authedUserId });

      callback({ success: true });
    } catch (err) {
      console.error('Error removing friend:', err);
      callback({ success: false, error: 'Failed to remove friend' });
    }
  });
}

module.exports = { registerContactsAccountSocketHandlers };
