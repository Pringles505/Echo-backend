const { registerAuthSocketHandlers } = require('./handlers/auth.handlers');
const { registerPresenceSocketHandlers } = require('./handlers/presence.handlers');
const { registerOpkSocketHandlers } = require('./handlers/opk.handlers');
const { registerDirectMessagingSocketHandlers } = require('./handlers/directMessaging.handlers');
const { registerGroupsSocketHandlers } = require('./handlers/groups.handlers');
const { registerCallsSocketHandlers } = require('./handlers/calls.handlers');
const { registerContactsAccountSocketHandlers } = require('./handlers/contactsAccount.handlers');
const { registerDeviceSyncSocketHandlers } = require('./handlers/deviceSync.handlers');
const { registerDeviceEnvelopeSocketHandlers } = require('./handlers/deviceEnvelope.handlers');

function registerSocketHandlers(deps) {
  const { socket, io, userSocketMap, models, services, authService, opkPolicy, opkLimiter, bcrypt, deviceSyncService } = deps;
  const { Message, User, MessageSequence, Group, GroupMember, GroupSequence, KeyPackage, Call, Device } = models;
  const { makeConversationKey, ensureConversationSequence, ensureGroupSequence, createCallEventMessage, saveProfilePicture } = services;

  const PUBLIC_EVENTS = new Set(['login', 'register']);
  socket.use((packet, next) => {
    const eventName = packet?.[0];
    const maybeAck = packet?.[packet.length - 1];
    const ack = typeof maybeAck === 'function' ? maybeAck : null;

    if (PUBLIC_EVENTS.has(eventName)) return next();
    if (!socket.user?.id) {
      if (ack) ack({ success: false, error: 'unauthorized', code: 'unauthorized' });
      return next(new Error('unauthorized'));
    }
    return next();
  });

  registerAuthSocketHandlers({ socket, authService });
  registerPresenceSocketHandlers({ socket, io, userSocketMap, Message, User });
  registerOpkSocketHandlers({
    socket,
    io,
    userSocketMap,
    User,
    Device,
    opkLimiter,
    ...opkPolicy,
  });
  registerDirectMessagingSocketHandlers({
    socket,
    io,
    userSocketMap,
    Message,
    User,
    MessageSequence,
    makeConversationKey,
    ensureConversationSequence,
  });
  registerGroupsSocketHandlers({
    socket,
    io,
    userSocketMap,
    Message,
    User,
    Group,
    GroupMember,
    GroupSequence,
    KeyPackage,
    ensureGroupSequence,
  });
  registerCallsSocketHandlers({
    socket,
    io,
    userSocketMap,
    Call,
    createCallEventMessage,
  });
  registerContactsAccountSocketHandlers({
    socket,
    io,
    userSocketMap,
    User,
    Message,
    bcrypt,
    saveProfilePicture,
  });
  registerDeviceSyncSocketHandlers({ socket, deviceSyncService });
  registerDeviceEnvelopeSocketHandlers({ socket });
}

module.exports = { registerSocketHandlers };
