/**
 * @module interfaces/http/routes/admin
 * Admin-only endpoints. All routes are gated by `requireAdmin`.
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createBlogService } = require('../../../modules/blog/application/blogService');
const {
  createEventsService,
} = require('../../../modules/community/application/eventsService');

/**
 * @param {object} deps
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} deps.requireAdmin
 * @param {{ BlogPost: any, Event: any, EventRegistration: any }} [deps.models]
 * @param {object} [deps.blogService]
 * @param {object} [deps.eventsService]
 * @returns {import('express').Router}
 */
function createAdminRouter(deps = {}) {
  const { mongoose, requireAdmin, models = {} } = deps;

  const blogService = deps.blogService || createBlogService({ BlogPost: models.BlogPost });
  const eventsService = deps.eventsService || createEventsService({
    Event: models.Event,
    EventRegistration: models.EventRegistration,
  });

  if (!mongoose) throw new Error('createAdminRouter requires mongoose');
  if (typeof requireAdmin !== 'function') {
    throw new Error('createAdminRouter requires requireAdmin middleware');
  }

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);

  function handleServiceError(res, next, err) {
    if (err && err.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /admin/blog:
   *   post:
   *     tags: [Admin]
   *     summary: Create a new blog post (admin)
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema: { $ref: '#/components/schemas/BlogPostRequest' }
   *     responses:
   *       201:
   *         description: Post created
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/BlogPostResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   */
  router.post(
    '/admin/blog',
    requireAdmin,
    dbGuard,
    validateBody([
      { field: 'title', type: 'string' },
      { field: 'content', type: 'string' },
      { field: 'slug', type: 'string', required: false },
      { field: 'excerpt', type: 'string', required: false },
      { field: 'coverImage', type: 'string', required: false },
      { field: 'tags', type: 'array', required: false },
      { field: 'status', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const post = await blogService.createPost({
          authorId: req.user?.id,
          title: req.body.title,
          content: req.body.content,
          slug: req.body.slug,
          excerpt: req.body.excerpt,
          coverImage: req.body.coverImage,
          tags: req.body.tags,
          status: req.body.status,
        });
        return res.status(201).json({ success: true, post });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /admin/blog/{id}:
   *   patch:
   *     tags: [Admin]
   *     summary: Update a blog post (admin)
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema: { type: string }
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema: { $ref: '#/components/schemas/BlogPostUpdateRequest' }
   *     responses:
   *       200:
   *         description: Post updated
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/BlogPostResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   */
  router.patch(
    '/admin/blog/:id',
    requireAdmin,
    dbGuard,
    async (req, res, next) => {
      try {
        const { id } = req.params;
        const post = await blogService.updatePost({ id, changes: req.body || {} });
        return res.json({ success: true, post });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  /**
   * @openapi
   * /admin/events:
   *   post:
   *     tags: [Admin]
   *     summary: Create a new event / hackathon (admin)
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema: { $ref: '#/components/schemas/EventRequest' }
   *     responses:
   *       201:
   *         description: Event created
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/EventResponse' }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   */
  router.post(
    '/admin/events',
    requireAdmin,
    dbGuard,
    validateBody([
      { field: 'title', type: 'string' },
      { field: 'startsAt', type: 'string' },
      { field: 'description', type: 'string', required: false },
      { field: 'eventType', type: 'string', required: false },
      { field: 'location', type: 'string', required: false },
      { field: 'endsAt', type: 'string', required: false },
      { field: 'capacity', type: 'number', required: false },
      { field: 'bannerImage', type: 'string', required: false },
      { field: 'status', type: 'string', required: false },
      { field: 'slug', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const event = await eventsService.createEvent({
          createdBy: req.user?.id,
          title: req.body.title,
          description: req.body.description,
          eventType: req.body.eventType,
          location: req.body.location,
          startsAt: req.body.startsAt,
          endsAt: req.body.endsAt,
          capacity: req.body.capacity,
          bannerImage: req.body.bannerImage,
          status: req.body.status,
          slug: req.body.slug,
        });
        return res.status(201).json({ success: true, event });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createAdminRouter };
