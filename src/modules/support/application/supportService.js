/**
 * @module modules/support/application/supportService
 *
 * Persists support ticket submissions from the public "contact" form.
 * No outbound email is sent — operators consume tickets from MongoDB or a
 * downstream admin UI.
 */

const { customAlphabet } = require('nanoid');
const { BadRequestError } = require('../../../shared/errors');
const {
  SUPPORT_MESSAGE_MAX_LENGTH,
  SUPPORT_SUBJECT_MAX_LENGTH,
} = require('../../../shared/constants');

const ticketIdGen = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 10);

const VALID_CATEGORIES = ['technical', 'account', 'billing', 'general'];

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 320 && EMAIL_RE.test(value.trim());
}

function createSupportService({ SupportTicket } = {}) {
  if (!SupportTicket) {
    throw new Error('createSupportService requires SupportTicket model');
  }

  return {
    /**
     * @param {object} input
     * @param {string} input.name
     * @param {string} input.email
     * @param {string} input.subject
     * @param {string} input.message
     * @param {'technical'|'account'|'billing'|'general'} [input.category]
     * @param {string|null} [input.userId]
     * @param {string|null} [input.ip]
     * @param {string|null} [input.userAgent]
     */
    async submitTicket({
      name,
      email,
      subject,
      message,
      category,
      userId,
      ip,
      userAgent,
    } = {}) {
      if (!isNonEmptyString(name)) {
        throw new BadRequestError('name is required', 'validation_error');
      }
      if (!isValidEmail(email)) {
        throw new BadRequestError('A valid email is required', 'validation_error');
      }
      if (!isNonEmptyString(subject)) {
        throw new BadRequestError('subject is required', 'validation_error');
      }
      if (subject.length > SUPPORT_SUBJECT_MAX_LENGTH) {
        throw new BadRequestError('subject is too long', 'validation_error');
      }
      if (!isNonEmptyString(message)) {
        throw new BadRequestError('message is required', 'validation_error');
      }
      if (message.length > SUPPORT_MESSAGE_MAX_LENGTH) {
        throw new BadRequestError('message is too long', 'validation_error');
      }

      const finalCategory = VALID_CATEGORIES.includes(category) ? category : 'general';

      const ticket = await SupportTicket.create({
        ticketId: ticketIdGen(),
        name: name.trim(),
        email: email.trim().toLowerCase(),
        subject: subject.trim(),
        message,
        category: finalCategory,
        status: 'open',
        userId: userId || null,
        ip: ip || null,
        userAgent: userAgent || null,
        createdAt: new Date(),
      });

      return {
        ticketId: ticket.ticketId,
        status: ticket.status,
        createdAt: ticket.createdAt,
      };
    },
  };
}

module.exports = { createSupportService };
