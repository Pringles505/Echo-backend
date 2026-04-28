/**
 * Service boundary for creating and emitting synthetic call-event messages.
 * @param {object} deps
 * @param {*} deps.io
 * @param {Record<string,string>} deps.userSocketMap
 * @param {import('mongoose').Model} deps.Call
 * @param {import('mongoose').Model} deps.Message
 * @param {import('mongoose').Model} deps.User
 */
function createCallEventService({ io, userSocketMap, Call, Message, User }) {
  async function createCallEventMessage({ callId, status, duration = 0 }) {
    try {
      const call = await Call.findOne({ callId });
      if (!call) {
        console.log('Call not found for event message:', callId);
        return null;
      }

      const existingCallEvent = await Message.findOne({
        messageType: 'call_event',
        'callData.callId': callId,
      });

      if (existingCallEvent) {
        console.log('⚠️ Call event message already exists for callId:', callId);
        return existingCallEvent;
      }

      const sender = await User.findOne({ id: call.callerId });
      if (!sender) {
        console.log('Sender not found:', call.callerId);
        return null;
      }

      const message = new Message({
        messageType: 'call_event',
        callData: {
          status,
          callType: call.callType,
          duration,
          callerId: call.callerId,
          receiverId: call.receiverId,
          callId: call.callId,
        },
        userId: call.callerId,
        targetUserId: call.receiverId,
        username: sender.username,
        seenStatus: false,
        messageNumber: 0,
        is_initial: false,
        payload: '',
        publicEphemeralKey: '',
      });

      await message.save();
      console.log('✅ Call event message saved:', status);

      const messageWithProfile = {
        ...message.toObject(),
        profileImage: sender.profilePicture || null,
        timestamp: message.createdAt,
      };

      const room = [call.callerId, call.receiverId].sort().join('_');
      io.to(room).emit('newMessage', messageWithProfile);

      const callerSocketId = userSocketMap[call.callerId];
      const receiverSocketId = userSocketMap[call.receiverId];

      if (callerSocketId) {
        const callerSocket = io.sockets.sockets.get(callerSocketId);
        if (!callerSocket || !callerSocket.rooms.has(room)) {
          io.to(callerSocketId).emit('newMessage', messageWithProfile);
        }
      }
      if (receiverSocketId) {
        const receiverSocket = io.sockets.sockets.get(receiverSocketId);
        if (!receiverSocket || !receiverSocket.rooms.has(room)) {
          io.to(receiverSocketId).emit('newMessage', messageWithProfile);
        }
      }

      return message;
    } catch (err) {
      console.error('Error creating call event message:', err);
      return null;
    }
  }

  return { createCallEventMessage };
}

module.exports = { createCallEventService };
