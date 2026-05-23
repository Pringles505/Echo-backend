const {
  DEVICE_ENVELOPE_TTL_SECONDS,
  OPK_REQUEST_LOG_TTL,
} = require('../../../shared/constants');

/**
 * Registers and returns all mongoose models used by the app.
 * This keeps persistence details out of the runtime bootstrap.
 */
function createModels(mongoose) {
  const userSchema = new mongoose.Schema({
    id: { type: String, unique: true },
    username: { type: String, unique: true },
    hashedPassword: String,
    friends: [String],
    devices: [{ type: String }],
    publicIdentityKeyX25519: String,
    publicIdentityKeyEd25519: String,
    signedPreKey: String,
    signature: String,
    signedPreKeyId: { type: Number, default: 0 },
    oneTimePreKeys: [
      {
        opkId: String,
        opkPub: String,
      },
    ],
    aboutme: { type: String, default: '' },
    profilePicture: { type: String, default: '' },
    banner: { type: String, default: '' },
    role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
  });

  const messageSchema = new mongoose.Schema({
    is_initial: Boolean,
    payload: String,
    nonce: String,
    userId: String,
    targetUserId: String,
    conversationKey: { type: String, default: null },
    username: String,
    messageNumber: Number,
    sendingNumber: Number,
    previousSendingNumber: Number,
    publicEphemeralKey: String,
    spkId: { type: mongoose.Schema.Types.Mixed, default: null },
    opkId: { type: String, default: null },
    // Per-device fanout: when set, the message was encrypted with the
    // sender's device IK against the recipient's specific device bundle.
    // Receivers other than `peerDeviceId` must ignore the event.
    senderDeviceId: { type: String, default: null },
    peerDeviceId: { type: String, default: null },
    senderDeviceUserId: { type: String, default: null },
    peerDeviceUserId: { type: String, default: null },
    conversationUserId: { type: String, default: null },
    seenStatus: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    messageType: {
      type: String,
      enum: ['text', 'image', 'tenor', 'call_event'],
      default: 'text',
    },
    callData: {
      status: {
        type: String,
        enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed'],
      },
      callType: String,
      duration: Number,
      callerId: String,
      receiverId: String,
      callId: String,
    },
    conversationType: {
      type: String,
      enum: ['direct', 'group'],
      default: 'direct',
    },
    groupId: { type: String, default: null, index: true },
    seq: { type: Number, default: null, index: true, groupId: 1, seq: 1 },
    epoch: { type: Number, default: null },
    senderLeafIndex: { type: Number, default: null },
    contentType: { type: String, enum: ['application', 'commit', 'welcome', 'proposal', null], default: null },
    headerB64: { type: String, default: null },
    ciphertextB64: { type: String, default: null },
    // Item #3: encrypted sender identity blob — server cannot read leaf index from this
    encryptedSenderDataB64: { type: String, default: null },
  });

  const messageSequenceSchema = new mongoose.Schema({
    conversationKey: { type: String, required: true, unique: true, index: true },
    participants: { type: [String], default: [] },
    lastMessageNumber: { type: Number, default: -1 },
    lastSenderId: { type: String, default: null },
    updatedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
  });

  const opkRequestLogSchema = new mongoose.Schema({
    requesterId: { type: String, index: true },
    targetUserId: { type: String, index: true },
    pairKey: { type: String, index: true },
    ip: String,
    userAgent: String,
    outcome: String,
    retryAfterMs: { type: Number, default: 0 },
    opkConsumed: { type: Boolean, default: false },
    opkId: { type: String, default: null },
    createdAt: { type: Date, default: Date.now, index: true },
  });
  opkRequestLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: OPK_REQUEST_LOG_TTL });

  const calls = new mongoose.Schema({
    callId: { type: String, unique: true },
    callerId: String,
    receiverId: String,
    startedAt: { type: Date, default: Date.now },
    endedAt: { type: Date, default: null },
    callType: { type: String, default: 'video' },
    status: {
      type: String,
      enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed'],
      default: 'ringing',
    },
    duration: { type: Number, default: 0 },
  });

  const groupSchema = new mongoose.Schema({
    groupId: { type: String, unique: true, index: true },
    name: String,
    createdAt: { type: Date, default: Date.now },
    createdBy: String,
    mlsEnabled: { type: Boolean, default: false },
    epoch: { type: Number, default: 0 },
    cipherSuite: { type: String, default: null },
  });

  const groupMemberSchema = new mongoose.Schema({
    groupId: { type: String, index: true },
    userId: { type: String, index: true },
    role: { type: String, enum: ['admin', 'member'], default: 'member' },
    joinedAt: { type: Date, default: Date.now },
    leafIndex: { type: Number, default: null },
    credential: { type: mongoose.Schema.Types.Mixed, default: null },
    status: { type: String, enum: ['active', 'invited', 'removed'], default: 'active' },
  });

  const groupSequenceSchema = new mongoose.Schema({
    groupId: { type: String, required: true, unique: true, index: true },
    lastSequenceNumber: { type: Number, default: -1 },
    updatedAt: { type: Date, default: Date.now },
  });

  const deviceSchema = new mongoose.Schema({
    // `deviceId` is the canonical opaque device identifier; unique across the
    // whole collection (one row per physical device). `deviceUserId` is the
    // synthetic per-device account id (e.g. "alice_x1") and is also unique.
    deviceId: { type: String, required: true, unique: true, index: true },
    parentUserId: { type: String, required: true, index: true },
    deviceUserId: { type: String, required: true, unique: true },
    deviceName: { type: String, default: 'Unknown device' },
    platform: { type: String, default: null },
    userAgent: { type: String, default: null },
    ipAddress: { type: String, default: null },
    ipLocation: { type: String, default: null },
    locale: { type: String, default: null },
    timezone: { type: String, default: null },
    isPrimary: { type: Boolean, default: false },
    isRevoked: { type: Boolean, default: false },
    publicIdentityKeyX25519: { type: String, default: null },
    publicIdentityKeyEd25519: { type: String, default: null },
    signedPreKey: { type: String, default: null },
    signedPreKeySignature: { type: String, default: null },
    signedPreKeyId: { type: Number, default: 0 },
    oneTimePreKeys: [{ opkId: String, opkPub: String }],
    deviceAuthorizationSignature: { type: String, default: null },
    provisionedVia: {
      type: String,
      enum: ['registration', 'pairing', 'device-sync'],
      default: 'registration',
    },
    createdAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: null },
  });
  // Used by listDevices, getDeviceBundles, and the per-user fanout query.
  deviceSchema.index({ parentUserId: 1, isRevoked: 1 });

  const pairingSessionSchema = new mongoose.Schema({
    sessionId: { type: String, required: true, unique: true, index: true },
    parentUserId: { type: String, required: true, index: true },
    primaryDeviceId: { type: String, default: null },
    status: {
      type: String,
      enum: ['pending', 'awaiting_approval', 'approved', 'rejected', 'expired'],
      default: 'pending',
    },
    challenge: { type: String, default: null },
    expiresAt: { type: Date, required: true, index: true },
    serverUrl: { type: String, default: null },
    newDeviceId: { type: String, default: null },
    newDeviceName: { type: String, default: null },
    newDevicePlatform: { type: String, default: null },
    newDeviceUserAgent: { type: String, default: null },
    newDeviceIpAddress: { type: String, default: null },
    newDeviceIpLocation: { type: String, default: null },
    newDeviceLocale: { type: String, default: null },
    newDeviceTimezone: { type: String, default: null },
    newDevicePublicIdentityKeyX25519: { type: String, default: null },
    newDevicePublicIdentityKeyEd25519: { type: String, default: null },
    newDeviceSignedPreKey: { type: String, default: null },
    newDeviceSignedPreKeySignature: { type: String, default: null },
    challengeResponse: { type: String, default: null },
    deviceAuthorizationSignature: { type: String, default: null },
    approvedDeviceUserId: { type: String, default: null },
    approvedToken: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
  });
  pairingSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86400 });

  const messageEnvelopeSchema = new mongoose.Schema({
    envelopeId: { type: String, required: true, unique: true, index: true },
    logicalSenderId: { type: String, index: true },
    senderDeviceId: { type: String, default: null },
    logicalRecipientId: { type: String, default: null },
    recipientDeviceId: { type: String, required: true, index: true },
    ciphertext: { type: String, required: true },
    nonce: { type: String, default: null },
    header: { type: mongoose.Schema.Types.Mixed, default: null },
    messageType: { type: String, default: 'message' },
    conversationId: { type: String, default: null, index: true },
    createdAt: { type: Date, default: Date.now, index: true },
    deliveredAt: { type: Date, default: null },
    readAt: { type: Date, default: null },
  });
  messageEnvelopeSchema.index({ createdAt: 1 }, { expireAfterSeconds: DEVICE_ENVELOPE_TTL_SECONDS });
  // Composite index used by envelopes fanout pull (sorted by createdAt).
  messageEnvelopeSchema.index({ recipientDeviceId: 1, deliveredAt: 1, createdAt: 1 });

  const deviceSyncSessionSchema = new mongoose.Schema({
    sessionId: { type: String, required: true, unique: true, index: true },
    status: {
      type: String,
      enum: ['pending_source', 'awaiting_confirmation', 'transferring', 'completed', 'cancelled', 'expired'],
      default: 'pending_source',
    },
    sessionCode: { type: String, default: null },
    targetEphemeralPubKey: { type: String, required: true },
    sourceEphemeralPubKey: { type: String, default: null },
    targetAccessTokenHash: { type: String, required: true },
    sourceUserId: { type: String, default: null, index: true },
    sourceUsername: { type: String, default: null },
    expiresAt: { type: Date, required: true, index: true },
    origin: { type: String, default: null },
    version: { type: String, default: null },
    approvedAt: { type: Date, default: null },
    completedAt: { type: Date, default: null },
    cancelledAt: { type: Date, default: null },
    totalChunkCount: { type: Number, default: 0 },
    totalPayloadBytes: { type: Number, default: 0 },
    sourceConfirmed: { type: Boolean, default: false },
    targetConfirmed: { type: Boolean, default: false },
    sourceDevice: { type: mongoose.Schema.Types.Mixed, default: {} },
    targetDevice: { type: mongoose.Schema.Types.Mixed, default: {} },
    // Target device public IK (no private material).
    targetDeviceIdentityPubX25519: { type: String, default: null },
    targetDeviceIdentityPubEd25519: { type: String, default: null },
    deviceAuthorizationSignature: { type: String, default: null },
    chunks: [
      {
        index: Number,
        totalCount: Number,
        ciphertext: String,
        nonce: { type: String, default: null },
        digest: String,
        size: Number,
      },
    ],
    createdAt: { type: Date, default: Date.now },
  });
  deviceSyncSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 86400 });

  const keyPackageSchema = new mongoose.Schema({
    // Item #20: userId is no longer unique alone — one record per (userId, clientId) pair
    // so multiple devices can publish independent KeyPackages.
    userId: { type: String, required: true, index: true },
    // Item #20: opaque device/client identifier; null means "only device" (legacy compat).
    clientId: { type: String, default: null },
    // Full signed KeyPackage blob (replaces the raw initKeyB64 field).
    keyPackage: { type: mongoose.Schema.Types.Mixed, default: null },
    initKeyB64: { type: String, default: null },
    // Item #9: pool lifecycle — once consumed for an Add commit the package is retired.
    consumed: { type: Boolean, default: false, index: true },
    createdAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now },
  });
  // Compound unique index: one active KeyPackage per (userId, clientId) pair.
  keyPackageSchema.index({ userId: 1, clientId: 1 }, { unique: true });

  const blogPostSchema = new mongoose.Schema({
    slug: { type: String, unique: true, index: true },
    title: { type: String, required: true },
    excerpt: { type: String, default: '' },
    content: { type: String, required: true },
    coverImage: { type: String, default: '' },
    tags: { type: [String], default: [] },
    authorId: { type: String, required: true, index: true },
    status: {
      type: String,
      enum: ['draft', 'published', 'archived'],
      default: 'draft',
      index: true,
    },
    publishedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  });

  const eventSchema = new mongoose.Schema({
    eventId: { type: String, unique: true, index: true },
    slug: { type: String, unique: true, index: true },
    title: { type: String, required: true },
    description: { type: String, default: '' },
    eventType: {
      type: String,
      enum: ['event', 'hackathon', 'workshop', 'meetup'],
      default: 'event',
    },
    location: { type: String, default: '' },
    startsAt: { type: Date, required: true, index: true },
    endsAt: { type: Date, default: null },
    capacity: { type: Number, default: 0 },
    registeredCount: { type: Number, default: 0 },
    bannerImage: { type: String, default: '' },
    status: {
      type: String,
      enum: ['draft', 'active', 'cancelled', 'ended'],
      default: 'draft',
      index: true,
    },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  });

  const eventRegistrationSchema = new mongoose.Schema({
    eventId: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true },
    status: {
      type: String,
      enum: ['registered', 'cancelled', 'attended'],
      default: 'registered',
    },
    registeredAt: { type: Date, default: Date.now },
  });
  eventRegistrationSchema.index({ eventId: 1, userId: 1 }, { unique: true });

  const newsletterSubscriberSchema = new mongoose.Schema({
    email: { type: String, unique: true, lowercase: true, trim: true, index: true },
    status: { type: String, enum: ['active', 'unsubscribed'], default: 'active' },
    source: { type: String, default: 'web' },
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
    subscribedAt: { type: Date, default: Date.now },
  });

  const refreshTokenSchema = new mongoose.Schema({
    tokenHash: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    deviceId: { type: String, default: null, index: true },
    deviceUserId: { type: String, default: null },
    platform: { type: String, default: null },
    expiresAt: { type: Date, required: true },
    revoked: { type: Boolean, default: false, index: true },
    revokedAt: { type: Date, default: null },
    replacedBy: { type: String, default: null },
    reusedAt: { type: Date, default: null },
    userAgent: { type: String, default: null },
    ip: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
  });
  refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  refreshTokenSchema.index({ userId: 1, revoked: 1 });

  const supportTicketSchema = new mongoose.Schema({
    ticketId: { type: String, unique: true, index: true },
    name: { type: String, required: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    subject: { type: String, required: true },
    category: {
      type: String,
      enum: ['technical', 'account', 'billing', 'general'],
      default: 'general',
    },
    message: { type: String, required: true },
    status: {
      type: String,
      enum: ['open', 'in_progress', 'resolved', 'closed'],
      default: 'open',
      index: true,
    },
    userId: { type: String, default: null },
    ip: { type: String, default: null },
    userAgent: { type: String, default: null },
    createdAt: { type: Date, default: Date.now, index: true },
  });

  const Message = mongoose.models.Message || mongoose.model('Message', messageSchema);
  const User = mongoose.models.User || mongoose.model('User', userSchema);
  const MessageSequence =
    mongoose.models.MessageSequence || mongoose.model('MessageSequence', messageSequenceSchema);
  const OpkRequestLog =
    mongoose.models.OpkRequestLog || mongoose.model('OpkRequestLog', opkRequestLogSchema);
  const Call = mongoose.models.Call || mongoose.model('Call', calls);
  const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);
  const GroupMember = mongoose.models.GroupMember || mongoose.model('GroupMember', groupMemberSchema);
  const GroupSequence =
    mongoose.models.GroupSequence || mongoose.model('GroupSequence', groupSequenceSchema);
  const KeyPackage = mongoose.models.KeyPackage || mongoose.model('KeyPackage', keyPackageSchema);
  const BlogPost = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema);
  const Event = mongoose.models.Event || mongoose.model('Event', eventSchema);
  const EventRegistration =
    mongoose.models.EventRegistration || mongoose.model('EventRegistration', eventRegistrationSchema);
  const NewsletterSubscriber =
    mongoose.models.NewsletterSubscriber ||
    mongoose.model('NewsletterSubscriber', newsletterSubscriberSchema);
  const SupportTicket =
    mongoose.models.SupportTicket || mongoose.model('SupportTicket', supportTicketSchema);
  const RefreshToken =
    mongoose.models.RefreshToken || mongoose.model('RefreshToken', refreshTokenSchema);
  const Device = mongoose.models.Device || mongoose.model('Device', deviceSchema);
  const PairingSession =
    mongoose.models.PairingSession || mongoose.model('PairingSession', pairingSessionSchema);
  const MessageEnvelope =
    mongoose.models.MessageEnvelope || mongoose.model('MessageEnvelope', messageEnvelopeSchema);
  const DeviceSyncSession =
    mongoose.models.DeviceSyncSession || mongoose.model('DeviceSyncSession', deviceSyncSessionSchema);

  return {
    Message,
    User,
    MessageSequence,
    OpkRequestLog,
    Call,
    Group,
    GroupMember,
    GroupSequence,
    KeyPackage,
    BlogPost,
    Event,
    EventRegistration,
    NewsletterSubscriber,
    SupportTicket,
    RefreshToken,
    Device,
    PairingSession,
    MessageEnvelope,
    DeviceSyncSession,
  };
}

async function syncKeyPackageIndexes(KeyPackage) {
  try {
    const droppedIndexes = await KeyPackage.syncIndexes();
    console.log('[MLS] KeyPackage indexes synced', droppedIndexes);
  } catch (err) {
    console.error('[MLS] Failed to sync KeyPackage indexes:', err);
  }
}

module.exports = {
  createModels,
  syncKeyPackageIndexes,
};
