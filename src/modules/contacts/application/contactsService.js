/**
 * @module modules/contacts/application/contactsService
 *
 * Application service for friend management. Mirrors the `addFriend` and
 * `removeFriend` socket handlers but is framework-agnostic. After a
 * successful mutation the service notifies both participants through the
 * injected notifier so realtime listeners stay in sync regardless of which
 * transport (HTTP or socket) initiated the request.
 */

const {
  BadRequestError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');

/**
 * @param {object} deps
 * @param {import('mongoose').Model} deps.User
 * @param {{ emitToUser: (userId: string, event: string, payload: object) => boolean }} [deps.notifier]
 */
function createContactsService({ User, notifier } = {}) {
  if (!User) throw new Error('createContactsService requires User model');

  function emit(userId, event, payload) {
    if (!notifier || typeof notifier.emitToUser !== 'function') return;
    try {
      notifier.emitToUser(userId, event, payload);
    } catch (_err) {
      // Notifier failures must never break the HTTP response — the mutation
      // already succeeded and clients can resync via REST.
    }
  }

  return {
    /**
     * Add a one-way friendship edge from `userId` → `friendId`.
     * Note: the original socket handler only mutates `user.friends` (not the
     * target). We replicate that exact behaviour to keep parity.
     *
     * @param {{ userId: string, friendId: string }} input
     */
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

    /**
     * Remove a friendship edge between `userId` and `friendId`.
     * Mirrors the socket handler which mutates BOTH sides of the relation.
     *
     * @param {{ userId: string, friendId: string }} input
     */
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
