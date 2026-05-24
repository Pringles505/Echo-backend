function registerPresenceSocketHandlers({ socket, io, userSocketMap, Message, User }) {
  if (socket.user?.id) {
    socket.join(socket.user.id);
    if (socket.user.deviceUserId) socket.join(socket.user.deviceUserId);
    socket.broadcast.emit('userOnline', { userId: socket.user.id });
    socket.emit('onlineUsersList', { onlineUsers: Object.keys(userSocketMap) });

    const authedId = String(socket.user.id);
    Message.find({
      conversationType: 'group',
      contentType: 'welcome',
      targetUserId: authedId,
    }).lean().then((stored) => {
      for (const msg of stored) {
        try {
          const welcome = JSON.parse(msg.payload);
          socket.emit('groupWelcome', { groupId: msg.groupId, welcome });
        } catch { }
      }
    }).catch((err) => {
      console.error('[MLS] Error pushing pending welcomes on connect:', err);
    });
  }

  socket.on('getOnlineUsers', (callback) => {
    callback({ onlineUsers: Object.keys(userSocketMap) });
  });

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
