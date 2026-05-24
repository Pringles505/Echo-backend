const { BadRequestError, NotFoundError, ForbiddenError } = require('../../../shared/errors');

const RING_TIMEOUT_MS = 30000;

function createCallsService({
  Call,
  callEventService,
  notifier,
  ringTimeoutMs = RING_TIMEOUT_MS,
  scheduleTimeout,
} = {}) {
  if (!Call) throw new Error('createCallsService requires Call');
  if (!callEventService || typeof callEventService.createCallEventMessage !== 'function') {
    throw new Error('createCallsService requires callEventService.createCallEventMessage');
  }
  if (!notifier || typeof notifier.emitToUser !== 'function') {
    throw new Error('createCallsService requires notifier with emitToUser()');
  }

  const setTimer = typeof scheduleTimeout === 'function' ? scheduleTimeout : setTimeout;

  function ensureParticipant(call, userId) {
    if (userId !== call.callerId && userId !== call.receiverId) {
      throw new ForbiddenError('Not a participant of this call', 'forbidden');
    }
  }

  async function loadCall(callId) {
    const call = await Call.findOne({ callId });
    if (!call) throw new NotFoundError('Call not found', 'not_found');
    return call;
  }

  // Re-reads from the DB and only acts when status is still 'ringing'.
  function scheduleMissedCheck(callId) {
    setTimer(async () => {
      try {
        const current = await Call.findOne({ callId });
        if (!current || current.status !== 'ringing') return;
        current.status = 'missed';
        current.endedAt = new Date();
        await current.save();
        await callEventService.createCallEventMessage({ callId, status: 'missed', duration: 0 });
      } catch (err) {
        console.error('Error marking missed call:', err);
      }
    }, ringTimeoutMs);
  }

  return {
    async initiateCall({ callerId, callerName, targetUserId, callId } = {}) {
      if (!callerId) throw new BadRequestError('Missing callerId', 'validation_error');
      if (!targetUserId) throw new BadRequestError('Missing targetUserId', 'validation_error');
      if (!callId) throw new BadRequestError('Missing callId', 'validation_error');

      if (notifier.isUserOnline && !notifier.isUserOnline(targetUserId)) {
        throw new BadRequestError('Target user is offline', 'target_offline');
      }

      const targetUserIdString = String(targetUserId);

      notifier.emitToUser(targetUserIdString, 'incomingCall', {
        callId,
        callerId,
        callerName,
      });

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

      scheduleMissedCheck(callId);

      return { status: 'ringing' };
    },

    async acceptCall({ userId, callId } = {}) {
      if (!userId) throw new BadRequestError('Missing userId', 'validation_error');
      if (!callId) throw new BadRequestError('Missing callId', 'validation_error');

      const call = await loadCall(callId);
      ensureParticipant(call, userId);

      call.status = 'in-progress';
      await call.save();

      notifier.emitToUser(call.callerId, 'callAccepted', { callId });

      return { status: 'in-progress' };
    },

    async declineCall({ userId, callId } = {}) {
      if (!userId) throw new BadRequestError('Missing userId', 'validation_error');
      if (!callId) throw new BadRequestError('Missing callId', 'validation_error');

      const call = await loadCall(callId);
      ensureParticipant(call, userId);

      notifier.emitToUser(call.callerId, 'callDeclined', { callId });

      await Call.findOneAndUpdate(
        { callId },
        { $set: { status: 'declined', endedAt: new Date(), duration: 0 } }
      );

      await callEventService.createCallEventMessage({ callId, status: 'declined', duration: 0 });

      return { status: 'declined' };
    },

    async endCall({ userId, callId } = {}) {
      if (!userId) throw new BadRequestError('Missing userId', 'validation_error');
      if (!callId) throw new BadRequestError('Missing callId', 'validation_error');

      const call = await loadCall(callId);
      ensureParticipant(call, userId);

      const otherUserId = userId === call.callerId ? call.receiverId : call.callerId;
      notifier.emitToUser(otherUserId, 'callEnded', { callId });

      const endedAt = new Date();
      const startedAt = call.startedAt instanceof Date ? call.startedAt : new Date(call.startedAt);
      const durationSeconds = Math.max(0, Math.round((endedAt - startedAt) / 1000));
      call.status = 'ended';
      call.endedAt = endedAt;
      call.duration = durationSeconds;
      await call.save();

      await callEventService.createCallEventMessage({
        callId,
        status: 'ended',
        duration: durationSeconds,
      });

      return { status: 'ended', duration: durationSeconds };
    },

    async updateMediaState({ userId, targetUserId, mediaType, isEnabled } = {}) {
      if (!userId) throw new BadRequestError('Missing userId', 'validation_error');
      if (!targetUserId) throw new BadRequestError('Missing targetUserId', 'validation_error');
      if (mediaType !== 'audio' && mediaType !== 'video') {
        throw new BadRequestError(
          "mediaType must be 'audio' or 'video'",
          'validation_error'
        );
      }
      if (typeof isEnabled !== 'boolean') {
        throw new BadRequestError('isEnabled must be a boolean', 'validation_error');
      }

      if (notifier.isUserOnline && !notifier.isUserOnline(targetUserId)) {
        throw new BadRequestError('Target user is offline', 'target_offline');
      }

      const event = mediaType === 'video' ? 'videoStateChanged' : 'audioStateChanged';
      notifier.emitToUser(String(targetUserId), event, { isEnabled });

      return { mediaType, isEnabled };
    },
  };
}

module.exports = { createCallsService, RING_TIMEOUT_MS };
