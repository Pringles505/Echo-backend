/**
 * Socket event handlers for voice and video calling.
 * Implements call lifecycle management (initiate, accept, decline, end)
 * and real-time media state synchronization.
 * @module interfaces/socket/handlers/calls
 */

/**
 * @typedef {object} InitiateCallPayload
 * @property {string} targetUserId - Recipient user ID
 * @property {string} callId - Unique call identifier
 */

/**
 * @typedef {object} AcceptCallPayload
 * @property {string} callId - Call ID to accept
 */

/**
 * @typedef {object} DeclineCallPayload
 * @property {string} callId - Call ID to decline
 */

/**
 * @typedef {object} EndCallPayload
 * @property {string} callId - Call ID to end
 */

/**
 * @typedef {object} MediaStatePayload
 * @property {string} targetUserId - Recipient user ID
 * @property {boolean} isEnabled - Media state (audio/video enabled)
 */

/**
 * @typedef {object} CaptionPayload
 * @property {string} targetUserId - Recipient user ID
 * @property {string} callId - Call ID for context
 * @property {string} text - Caption text
 */

/**
 * Registers Socket.IO handlers for call signaling and media state.
 * Manages call lifecycle and real-time caption/media event distribution.
 *
 * @param {object} deps - Handler dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server instance
 * @param {Record<string,string>} deps.userSocketMap - Map of user ID to socket ID
 * @param {import('mongoose').Model} deps.Call - Call model
 * @param {function} deps.createCallEventMessage - Service to create call event records
 */
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

  /**
   * 'initiateCall' event - Initiate a call to another user.
   * Emits 'incomingCall' to recipient and creates call record with 'ringing' status.
   * Auto-marks as 'missed' after 30 seconds if not accepted.
   * @event initiateCall
   * @type {InitiateCallPayload}
   */
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

  /**
   * 'acceptCall' event - Accept an incoming call.
   * Updates call status to 'in-progress' and notifies caller.
   * @event acceptCall
   * @type {AcceptCallPayload}
   */
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

  /**
   * 'declineCall' event - Decline an incoming call.
   * Updates call status to 'declined' and notifies caller.
   * @event declineCall
   * @type {DeclineCallPayload}
   */
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

  /**
   * 'endCall' event - End an active call.
   * Calculates duration, updates call status to 'ended', and notifies peer.
   * @event endCall
   * @type {EndCallPayload}
   */
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

  /**
   * 'videoStateChanged' event - Broadcast video enable/disable.
   * Notifies peer of local video state change.
   * @event videoStateChanged
   * @type {MediaStatePayload}
   */
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

  /**
   * 'audioStateChanged' event - Broadcast audio enable/disable.
   * Notifies peer of local audio state change.
   * @event audioStateChanged
   * @type {MediaStatePayload}
   */
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

  /**
   * 'captionInterim' event - Send interim (live) caption during call.
   * Notifies peer of caption text as user speaks (not yet finalized).
   * @event captionInterim
   * @type {CaptionPayload}
   */
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

  /**
   * 'captionFinal' event - Send finalized caption during call.
   * Notifies peer of caption text after speech recognition completes.
   * @event captionFinal
   * @type {CaptionPayload}
   */
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
