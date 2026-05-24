const {
  BadRequestError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');

function createContactsService({ User, notifier } = {}) {
  if (!User) throw new Error('createContactsService requires User model');

  function emit(userId, event, payload) {
    if (!notifier || typeof notifier.emitToUser !== 'function') return;
    try {
      notifier.emitToUser(userId, event, payload);
    } catch (_err) {
      // Notifier failures must never break the HTTP response; clients can resync via REST.
    }
  }

  return {
    async listContacts({ userId }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      const me = await User.findOne({ id: userId }).lean();
      if (!me) throw new NotFoundError('User not found', 'user_not_found');
      const friendIds = Array.isArray(me.friends) ? me.friends : [];
      if (friendIds.length === 0) return { contacts: [] };
      const docs = await User.find({ id: { $in: friendIds } }).lean();
      const contacts = docs.map((u) => ({
        id: u.id,
        username: u.username,
        aboutme: u.aboutme || '',
        profilePicture: u.profilePicture || '',
        banner: u.banner || '',
      }));
      return { contacts };
    },

    // One-way friendship edge from `userId` → `friendId`. Matches the socket
    // handler which only mutates `user.friends`.
    async addFriend({ userId, friendId }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (typeof friendId !== 'string' || friendId.length === 0) {
        throw new BadRequestError('friendId is required', 'validation_error');
      }
      if (userId === friendId) {
        throw new BadRequestError('Cannot add yourself as a friend', 'self_friend');
      }

      const [user, target] = await Promise.all([
        User.findOne({ id: userId }),
        User.findOne({ id: friendId }),
      ]);
      if (!user || !target) {
        throw new NotFoundError('User(s) not found', 'user_not_found');
      }
      if (Array.isArray(user.friends) && user.friends.includes(friendId)) {
        throw new ConflictError('Already friends', 'already_friends');
      }

      user.friends = Array.isArray(user.friends) ? user.friends : [];
      user.friends.push(friendId);
      await user.save();

      emit(userId, 'friendAdded', {
        friendId,
        friendUsername: target.username,
      });
      emit(friendId, 'friendAdded', {
        friendId: userId,
        friendUsername: user.username,
      });

      return { added: true, friendId };
    },

    // Mutates BOTH sides of the relation.
    async removeFriend({ userId, friendId }) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new BadRequestError('userId is required', 'validation_error');
      }
      if (typeof friendId !== 'string' || friendId.length === 0) {
        throw new BadRequestError('friendId is required', 'validation_error');
      }
      if (userId === friendId) {
        throw new BadRequestError('Cannot remove yourself', 'self_friend');
      }

      const [user, target] = await Promise.all([
        User.findOne({ id: userId }),
        User.findOne({ id: friendId }),
      ]);
      if (!user || !target) {
        throw new NotFoundError('User(s) not found', 'user_not_found');
      }

      const userFriendIndex = Array.isArray(user.friends) ? user.friends.indexOf(friendId) : -1;
      const targetFriendIndex = Array.isArray(target.friends) ? target.friends.indexOf(userId) : -1;
      if (userFriendIndex === -1 || targetFriendIndex === -1) {
        throw new ConflictError('Not friends', 'not_friends');
      }

      user.friends.splice(userFriendIndex, 1);
      target.friends.splice(targetFriendIndex, 1);
      await Promise.all([user.save(), target.save()]);

      emit(userId, 'friendRemoved', { friendId });
      emit(friendId, 'friendRemoved', { friendId: userId });

      return { removed: true, friendId };
    },
  };
}

module.exports = { createContactsService };
