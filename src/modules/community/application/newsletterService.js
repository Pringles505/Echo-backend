const { BadRequestError } = require('../../../shared/errors');

// HTML5 input[type=email] regex.
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 320 && EMAIL_RE.test(value.trim());
}

function createNewsletterService({ NewsletterSubscriber } = {}) {
  if (!NewsletterSubscriber) {
    throw new Error('createNewsletterService requires NewsletterSubscriber model');
  }

  return {
    async subscribe({ email, source, ip, userAgent } = {}) {
      if (!isValidEmail(email)) {
        throw new BadRequestError('A valid email is required', 'validation_error');
      }
      const normalized = email.trim().toLowerCase();
      const now = new Date();
      const update = {
        status: 'active',
        source: typeof source === 'string' && source.length > 0 ? source : 'web',
        ip: ip || null,
        userAgent: userAgent || null,
        subscribedAt: now,
      };
      const doc = await NewsletterSubscriber.findOneAndUpdate(
        { email: normalized },
        { $set: update, $setOnInsert: { email: normalized } },
        { upsert: true, new: true, lean: true }
      );
      return {
        email: doc.email,
        status: doc.status,
        subscribedAt: doc.subscribedAt,
      };
    },
  };
}

module.exports = { createNewsletterService };
