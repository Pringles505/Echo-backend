// Public blog read endpoints. Admin writes live in `admin.route.js`.

const express = require('express');
const { requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createBlogService } = require('../../../modules/blog/application/blogService');

function createBlogRouter(deps = {}) {
  const { mongoose, models = {} } = deps;
  const blogService = deps.blogService || createBlogService({ BlogPost: models.BlogPost });

  if (!mongoose) throw new Error('createBlogRouter requires mongoose');

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
   * /blog/posts/{slug}:
   *   get:
   *     tags: [Blog]
   *     summary: Get a published blog post by slug
   *     security: []
   *     parameters:
   *       - in: path
   *         name: slug
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       200:
   *         description: Post found
   *         content:
   *           application/json:
   *             schema: { $ref: '#/components/schemas/BlogPostResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.get(
    '/blog/posts/:slug',
    dbGuard,
    async (req, res, next) => {
      try {
        const { slug } = req.params;
        const post = await blogService.getPostBySlug({ slug });
        return res.json({ success: true, post });
      } catch (err) {
        return handleServiceError(res, next, err);
      }
    }
  );

  return router;
}

module.exports = { createBlogRouter };
