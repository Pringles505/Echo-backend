const { registerAuthSocketHandlers } = require('./handlers/auth.handlers');
const { registerPresenceSocketHandlers } = require('./handlers/presence.handlers');
const { registerOpkSocketHandlers } = require('./handlers/opk.handlers');
const { registerDirectMessagingSocketHandlers } = require('./handlers/directMessaging.handlers');
const { registerGroupsSocketHandlers } = require('./handlers/groups.handlers');
const { registerCallsSocketHandlers } = require('./handlers/calls.handlers');
const { registerContactsAccountSocketHandlers } = require('./handlers/contactsAccount.handlers');

/**
 * Public socket adapter entrypoint for binding all runtime handlers.
 * Preserves legacy event names and ack payload contracts.
 * @param {object} deps
 * @param {*} deps.socket
 * @param {*} deps.io
 * @param {Record<string,string>} deps.userSocketMap
 * @param {object} deps.models
 * @param {object} deps.services
 * @param {object} deps.authService
 * @param {object} deps.opkPolicy
 * @param {object} deps.opkLimiter
 */
function registerSocketHandlers(deps) {
  const { socket, io, userSocketMap, models, services, authService, opkPolicy, opkLimiter, bcrypt } = deps;
  const { Message, User, MessageSequence, Group, GroupMember, GroupSequence, KeyPackage, Call } = models;
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
}

module.exports = { registerSocketHandlers };
