/**
 * Socket event handlers for user presence and status.
 * @module interfaces/socket/handlers/presence
 */

/**
 * @typedef {object} OnlineUsersPayload
 * @property {Array<string>} onlineUsers - List of online user IDs
 */

/**
 * @typedef {object} FetchUsernameAckResponse
 * @property {boolean} success
 * @property {string} [username] - Username if successful
 * @property {string} [error] - Error message if failed
 */

/**
 * Registers presence and lightweight user lookup events.
 * Handles user online/offline broadcasts and message synchronization on connection.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
 * @param {import('mongoose').Model} deps.Message - Message model
 * @param {import('mongoose').Model} deps.User - User model
 */
function registerPresenceSocketHandlers({ socket, io, userSocketMap, Message, User }) {
  if (socket.user?.id) {
    socket.join(socket.user.id);
    if (socket.user.deviceUserId) socket.join(socket.user.deviceUserId);
    socket.broadcast.emit('userOnline', { userId: socket.user.id });
    socket.emit('onlineUsersList', { onlineUsers: Object.keys(userSocketMap) });

    const authedId = String(socket.user.id);
    const welcomeTargetIds = new Set([authedId]);
    if (socket.user.deviceUserId) welcomeTargetIds.add(String(socket.user.deviceUserId));
    User.findOne({ id: authedId }, { devices: 1 })
      .lean()
      .then((parent) => {
        for (const deviceUserId of parent?.devices ?? []) {
          if (deviceUserId) welcomeTargetIds.add(String(deviceUserId));
        }
        return Message.find({
          conversationType: 'group',
          contentType: 'welcome',
          targetUserId: { $in: Array.from(welcomeTargetIds) },
        }).lean();
      })
      .then((stored) => {
      const thisDeviceClientId = socket.user?.deviceId ? String(socket.user.deviceId) : null;
      for (const msg of stored) {
        try {
          const welcome = JSON.parse(msg.payload);
          const targetClientId = welcome?.recipientClientId ?? null;
          if (
            targetClientId !== null &&
            thisDeviceClientId &&
            targetClientId !== thisDeviceClientId
          ) {
            continue;
          }
          socket.emit('groupWelcome', { groupId: msg.groupId, welcome });
        } catch { }
      }
    }).catch((err) => {
      console.error('[MLS] Error pushing pending welcomes on connect:', err);
    });
  }

  /**
   * 'getOnlineUsers' event - Retrieve current list of online users.
   * @event getOnlineUsers
   * @param {function} callback - (OnlineUsersPayload) => void
   */
  socket.on('getOnlineUsers', (callback) => {
    callback({ onlineUsers: Object.keys(userSocketMap) });
  });

  /**
   * 'fetchUsername' event - Look up username for a user ID.
   * @event fetchUsername
   * @param {string} userId - Target user ID
   * @param {function} callback - (FetchUsernameAckResponse) => void
   */
  socket.on('fetchUsername', async (userId, callback) => {
    console.log('Fetching username for user:', userId);
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        callback({ success: true, username: user.username });
      } else {
        callback({ success: false, error: 'User not found' });
      }
    } catch (error) {
      console.error('Error fetching username:', error);
      callback({ success: false, error: 'Internal server error' });
    }
  });

  /**
   * 'ready' event - Signal readiness for direct message conversation.
   * Joins a private room and synchronizes message history.
   * @event ready
   * @param {object} data
   * @param {string} data.targetUserId - Target user for conversation
   */
  socket.on('ready', async ({ targetUserId }) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !targetUserId) return;

    console.log(`User ${authedUserId} is opening chat with ${targetUserId}`);

    const room = [authedUserId, targetUserId].sort().join('_');
    socket.join(room);

    try {
      const message = await Message.find({
        $or: [
          { userId: authedUserId, targetUserId },
          { userId: targetUserId, targetUserId: authedUserId },
        ],
      }).sort({ createdAt: 1 });

      console.log(`Sending ${message.length} messages to User ${authedUserId} ↔ ${targetUserId}`);
      socket.emit('newMessage', message);
    } catch (err) {
      console.error('Error fetching messages:', err);
    }
  });

  /**
   * 'typing' event - Relay a typing indicator to the peer of a 1:1 chat.
   * Ephemeral; carries no message content, only the typist's user id. The
   * peer's user room is always joined, so this reaches every device of the
   * peer (active chat popup + conversation preview).
   * @event typing
   * @param {object} data
   * @param {string} data.targetUserId - The peer to notify.
   */
  socket.on('typing', ({ targetUserId } = {}) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !targetUserId) return;
    io.to(String(targetUserId)).emit('peerTyping', { userId: authedUserId });
  });

  /**
   * 'stopTyping' event - Clear a previously sent typing indicator.
   * @event stopTyping
   * @param {object} data
   * @param {string} data.targetUserId - The peer to notify.
   */
  socket.on('stopTyping', ({ targetUserId } = {}) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId || !targetUserId) return;
    io.to(String(targetUserId)).emit('peerStopTyping', { userId: authedUserId });
  });

  /**
   * 'disconnect' event - Handle socket disconnection and cleanup.
   * Removes user from online map and broadcasts offline event.
   * @event disconnect
   */
  socket.on('disconnect', () => {
    console.log(`🔴User with socket ID ${socket.id} disconnected.🔴`);

    for (const userId in userSocketMap) {
      if (userSocketMap[userId] === socket.id) {
        delete userSocketMap[userId];
        socket.broadcast.emit('userOffline', { userId });
        break;
      }
    }
  });
}

module.exports = { registerPresenceSocketHandlers };
