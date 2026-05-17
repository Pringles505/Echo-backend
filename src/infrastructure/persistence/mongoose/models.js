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
  opkRequestLogSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 });

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
