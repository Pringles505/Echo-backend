function registerCallsSocketHandlers({ socket, io, userSocketMap, Call, createCallEventMessage }) {
  const ackWith = (callback, payload) => {
    if (typeof callback === 'function') callback(payload);
  };

  const ackError = (callback, error, code) => {
    ackWith(callback, { success: false, error, code });
  };

  const ackSuccess = (callback, payload = {}) => {
    ackWith(callback, { success: true, ...payload });
  };

  // Auto-marks as 'missed' after 30s if the receiver never accepts.
  socket.on('initiateCall', async ({ targetUserId, callId } = {}, callback) => {
    const callerId = socket.user?.id;
    const callerName = socket.user?.username;
    if (!callerId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!targetUserId || !callId) {
      return ackError(callback, 'Missing required fields', 'missing_required_fields');
    }

    const targetSocketId = userSocketMap[targetUserId];
    const targetUserIdString = String(targetUserId);
    if (!targetSocketId) {
      return ackError(callback, 'Target user is offline', 'target_offline');
    }

    try {
      io.to(targetSocketId).emit('incomingCall', { callId, callerId, callerName });

      const call = new Call({
        callId,
        callerId,
        receiverId: targetUserIdString,
        status: 'ringing',
        startedAt: new Date(),
        endedAt: null,
        callType: 'video',
        duration: 0,
      });
      await call.save();
      ackSuccess(callback, { status: 'ringing' });

      setTimeout(async () => {
        try {
          const currentCall = await Call.findOne({ callId });
          if (currentCall && currentCall.status === 'ringing') {
            currentCall.status = 'missed';
            currentCall.endedAt = new Date();
            await currentCall.save();
            await createCallEventMessage({ callId, status: 'missed', duration: 0 });
          }
        } catch (err) {
          console.error('Error marking missed call:', err);
        }
      }, 30000);
    } catch (err) {
      console.error('Error initiating call:', err);
      ackError(callback, 'Internal server error', 'internal_error');
    }
  });

  socket.on('acceptCall', async ({ callId } = {}, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!callId) return ackError(callback, 'Missing required fields', 'missing_required_fields');

    try {
      const call = await Call.findOne({ callId });
      if (!call) return ackError(callback, 'Call not found', 'not_found');
      if (authedUserId !== call.receiverId && authedUserId !== call.callerId) {
        return ackError(callback, 'forbidden', 'forbidden');
      }

      call.status = 'in-progress';
      await call.save();

      const callerSocketId = userSocketMap[call.callerId];
      if (callerSocketId) io.to(callerSocketId).emit('callAccepted', { callId });
      ackSuccess(callback, { status: 'in-progress' });
    } catch (err) {
      console.error('Error in acceptCall:', err);
      ackError(callback, 'Internal server error', 'internal_error');
    }
  });

  socket.on('declineCall', async ({ callId } = {}, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!callId) return ackError(callback, 'Missing required fields', 'missing_required_fields');

    try {
      const call = await Call.findOne({ callId });
      if (!call) return ackError(callback, 'Call not found', 'not_found');
      if (authedUserId !== call.receiverId && authedUserId !== call.callerId) {
        return ackError(callback, 'forbidden', 'forbidden');
      }

      const callerSocketId = userSocketMap[call.callerId];
      if (callerSocketId) io.to(callerSocketId).emit('callDeclined', { callId });

      await Call.findOneAndUpdate(
        { callId },
        { $set: { status: 'declined', endedAt: new Date(), duration: 0 } }
      );

      await createCallEventMessage({ callId, status: 'declined', duration: 0 });
      ackSuccess(callback, { status: 'declined' });
    } catch (err) {
      console.error('Error updating declined call:', err);
      ackError(callback, 'Internal server error', 'internal_error');
    }
  });

  socket.on('endCall', async ({ callId } = {}, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!callId) return ackError(callback, 'Missing required fields', 'missing_required_fields');

    try {
      const call = await Call.findOne({ callId });
      if (!call) return ackError(callback, 'Call not found', 'not_found');
      if (authedUserId !== call.receiverId && authedUserId !== call.callerId) {
        return ackError(callback, 'forbidden', 'forbidden');
      }

      const otherUserId = authedUserId === call.callerId ? call.receiverId : call.callerId;
      const targetSocketId = userSocketMap[otherUserId];
      if (targetSocketId) io.to(targetSocketId).emit('callEnded', { callId });

      const endedAt = new Date();
      const durationSeconds = Math.max(0, Math.round((endedAt - call.startedAt) / 1000));
      call.status = 'ended';
      call.endedAt = endedAt;
      call.duration = durationSeconds;
      await call.save();

      await createCallEventMessage({ callId, status: 'ended', duration: durationSeconds });
      ackSuccess(callback, { status: 'ended', duration: durationSeconds });
    } catch (err) {
      console.error('Error ending call:', err);
      ackError(callback, 'Internal server error', 'internal_error');
    }
  });

  socket.on('videoStateChanged', ({ targetUserId, isEnabled } = {}, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!targetUserId || typeof isEnabled !== 'boolean') {
      return ackError(callback, 'Missing required fields', 'missing_required_fields');
    }

    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return ackError(callback, 'Target user is offline', 'target_offline');

    io.to(targetSocketId).emit('videoStateChanged', { isEnabled });
    ackSuccess(callback);
  });

  socket.on('audioStateChanged', ({ targetUserId, isEnabled } = {}, callback) => {
    const authedUserId = socket.user?.id;
    if (!authedUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    if (!targetUserId || typeof isEnabled !== 'boolean') {
      return ackError(callback, 'Missing required fields', 'missing_required_fields');
    }

    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return ackError(callback, 'Target user is offline', 'target_offline');

    io.to(targetSocketId).emit('audioStateChanged', { isEnabled });
    ackSuccess(callback);
  });

  socket.on('captionInterim', ({ targetUserId, callId, text } = {}, callback) => {
    if (typeof text !== 'string' || text.trim().length === 0) {
      return ackError(callback, 'Missing required fields', 'missing_required_fields');
    }
    const fromUserId = socket.user?.id;
    const fromUsername = socket.user?.username;
    if (!fromUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return ackError(callback, 'Target user is offline', 'target_offline');

    io.to(targetSocketId).emit('captionInterim', {
      callId,
      text: text.trim(),
      fromUserId,
      fromUsername,
    });
    ackSuccess(callback);
  });

  socket.on('captionFinal', ({ targetUserId, callId, text } = {}, callback) => {
    if (typeof text !== 'string' || text.trim().length === 0) {
      return ackError(callback, 'Missing required fields', 'missing_required_fields');
    }
    const fromUserId = socket.user?.id;
    const fromUsername = socket.user?.username;
    if (!fromUserId) return ackError(callback, 'unauthorized', 'unauthorized');
    const targetSocketId = userSocketMap[targetUserId];
    if (!targetSocketId) return ackError(callback, 'Target user is offline', 'target_offline');

    io.to(targetSocketId).emit('captionFinal', {
      callId,
      text: text.trim(),
      fromUserId,
      fromUsername,
    });
    ackSuccess(callback);
  });
}

module.exports = { registerCallsSocketHandlers };
