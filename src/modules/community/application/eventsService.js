const { customAlphabet } = require('nanoid');
const {
  BadRequestError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');
const {
  EVENT_LIST_DEFAULT_LIMIT,
  EVENT_LIST_MAX_LIMIT,
  BLOG_SLUG_MAX_LENGTH,
  BLOG_TITLE_MAX_LENGTH,
} = require('../../../shared/constants');

const eventIdGen = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8);
const slugSuffix = customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', 6);

const VALID_TYPES = ['event', 'hackathon', 'workshop', 'meetup'];
const VALID_STATUS = ['draft', 'active', 'cancelled', 'ended'];

function slugify(input) {
  if (typeof input !== 'string') return '';
  return input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, BLOG_SLUG_MAX_LENGTH);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function clampLimit(value) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n <= 0) return EVENT_LIST_DEFAULT_LIMIT;
  return Math.min(n, EVENT_LIST_MAX_LIMIT);
}

function createEventsService({ Event, EventRegistration } = {}) {
  if (!Event) throw new Error('createEventsService requires Event model');
  if (!EventRegistration) {
    throw new Error('createEventsService requires EventRegistration model');
  }

  return {
    async listActiveEvents({ type, status, page, limit } = {}) {
      const filter = {};
      filter.status = VALID_STATUS.includes(status) ? status : 'active';
      if (VALID_TYPES.includes(type)) filter.eventType = type;

      const safeLimit = clampLimit(limit);
      const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
      const skip = (safePage - 1) * safeLimit;

      const [items, total] = await Promise.all([
        Event.find(filter)
          .sort({ startsAt: 1 })
          .skip(skip)
          .limit(safeLimit)
          .lean(),
        Event.countDocuments(filter),
      ]);

      return {
        events: items.map((e) => ({
          eventId: e.eventId,
          slug: e.slug,
          title: e.title,
          description: e.description,
          eventType: e.eventType,
          location: e.location,
          startsAt: e.startsAt,
          endsAt: e.endsAt,
          capacity: e.capacity,
          registeredCount: e.registeredCount,
          bannerImage: e.bannerImage,
          status: e.status,
        })),
        page: safePage,
        limit: safeLimit,
        total,
      };
    },

    async createEvent({
      createdBy,
      title,
      description,
      eventType,
      location,
      startsAt,
      endsAt,
      capacity,
      bannerImage,
      status,
      slug,
    }) {
      if (!isNonEmptyString(createdBy)) {
        throw new BadRequestError('createdBy is required', 'validation_error');
      }
      if (!isNonEmptyString(title)) {
        throw new BadRequestError('title is required', 'validation_error');
      }
      if (title.length > BLOG_TITLE_MAX_LENGTH) {
        throw new BadRequestError('title exceeds max length', 'validation_error');
      }
      const start = startsAt ? new Date(startsAt) : null;
      if (!start || Number.isNaN(start.getTime())) {
        throw new BadRequestError('startsAt must be a valid date', 'validation_error');
      }
      const end = endsAt ? new Date(endsAt) : null;
      if (end && Number.isNaN(end.getTime())) {
        throw new BadRequestError('endsAt must be a valid date', 'validation_error');
      }
      if (end && end < start) {
        throw new BadRequestError('endsAt must be after startsAt', 'validation_error');
      }
      const finalType = VALID_TYPES.includes(eventType) ? eventType : 'event';
      const finalStatus = VALID_STATUS.includes(status) ? status : 'draft';

      const baseSlug = isNonEmptyString(slug) ? slugify(slug) : slugify(title);
      if (!baseSlug) {
        throw new BadRequestError('Unable to derive slug from title', 'validation_error');
      }
      let candidateSlug = baseSlug;
      const slugExists = await Event.findOne({ slug: candidateSlug }, { _id: 1 }).lean();
      if (slugExists) {
        candidateSlug = `${baseSlug.slice(0, BLOG_SLUG_MAX_LENGTH - 7)}-${slugSuffix()}`;
      }

      const cap = Number.parseInt(capacity, 10);
      const safeCapacity = Number.isFinite(cap) && cap >= 0 ? cap : 0;

      const now = new Date();
      const doc = new Event({
        eventId: eventIdGen(),
        slug: candidateSlug,
        title,
        description: typeof description === 'string' ? description : '',
        eventType: finalType,
        location: typeof location === 'string' ? location : '',
        startsAt: start,
        endsAt: end,
        capacity: safeCapacity,
        registeredCount: 0,
        bannerImage: typeof bannerImage === 'string' ? bannerImage : '',
        status: finalStatus,
        createdBy,
        createdAt: now,
        updatedAt: now,
      });

      try {
        await doc.save();
      } catch (err) {
        if (err?.code === 11000) {
          throw new ConflictError('Event id/slug already exists', 'event_conflict');
        }
        throw err;
      }
      return doc.toObject();
    },

    // Capacity is reserved atomically via a conditional `$inc` so concurrent
    // registrations cannot oversubscribe past `capacity`. If the registration
    // insert fails the reservation is rolled back with a compensating `$inc: -1`.
    async registerForEvent({ eventId, userId }) {
      if (!isNonEmptyString(eventId)) {
        throw new BadRequestError('eventId is required', 'validation_error');
      }
      if (!isNonEmptyString(userId)) {
        throw new BadRequestError('userId is required', 'validation_error');
      }

      const reserved = await Event.findOneAndUpdate(
        {
          eventId,
          status: 'active',
          $or: [
            { capacity: { $lte: 0 } },
            { $expr: { $lt: ['$registeredCount', '$capacity'] } },
          ],
        },
        { $inc: { registeredCount: 1 } },
        { new: true }
      ).lean();

      if (!reserved) {
        const event = await Event.findOne({ eventId }).lean();
        if (!event) throw new NotFoundError('Event not found', 'event_not_found');
        if (event.status !== 'active') {
          throw new BadRequestError('Event is not open for registration', 'event_not_active');
        }
        throw new ConflictError('Event is full', 'event_full');
      }

      try {
        await EventRegistration.create({
          eventId,
          userId,
          status: 'registered',
          registeredAt: new Date(),
        });
      } catch (err) {
        await Event.updateOne({ eventId }, { $inc: { registeredCount: -1 } });
        if (err?.code === 11000) {
          throw new ConflictError('Already registered', 'already_registered');
        }
        throw err;
      }

      return { registered: true, eventId, userId };
    },
  };
}

module.exports = { createEventsService };
