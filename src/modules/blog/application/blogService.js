/**
 * @module modules/blog/application/blogService
 *
 * Application service for the blog use cases. Public reads (by slug) only
 * return `published` posts; admin writes accept partial payloads via
 * `updatePost` and gate by status transitions.
 */

const { customAlphabet } = require('nanoid');
const {
  BadRequestError,
  NotFoundError,
  ConflictError,
} = require('../../../shared/errors');
const {
  BLOG_SLUG_MAX_LENGTH,
  BLOG_TITLE_MAX_LENGTH,
} = require('../../../shared/constants');

const SLUG_SUFFIX_LEN = 6;
const slugSuffix = customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', SLUG_SUFFIX_LEN);

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

function createBlogService({ BlogPost } = {}) {
  if (!BlogPost) throw new Error('createBlogService requires BlogPost model');

  return {
    /**
     * @param {{ slug: string }} input
     * @returns {Promise<object>}
     */
    async getPostBySlug({ slug }) {
      if (!isNonEmptyString(slug)) {
        throw new BadRequestError('slug is required', 'validation_error');
      }
      const post = await BlogPost.findOne({ slug, status: 'published' }).lean();
      if (!post) throw new NotFoundError('Post not found', 'post_not_found');
      return {
        slug: post.slug,
        title: post.title,
        excerpt: post.excerpt,
        content: post.content,
        coverImage: post.coverImage,
        tags: post.tags,
        authorId: post.authorId,
        publishedAt: post.publishedAt,
      };
    },

    /**
     * Admin: create a new blog post.
     * @param {object} input
     * @param {string} input.authorId - admin user id
     * @param {string} input.title
     * @param {string} input.content
     * @param {string} [input.slug] - auto-generated from title when omitted
     * @param {string} [input.excerpt]
     * @param {string} [input.coverImage]
     * @param {Array<string>} [input.tags]
     * @param {'draft'|'published'|'archived'} [input.status]
     */
    async createPost({ authorId, title, content, slug, excerpt, coverImage, tags, status }) {
      if (!isNonEmptyString(authorId)) {
        throw new BadRequestError('authorId is required', 'validation_error');
      }
      if (!isNonEmptyString(title)) {
        throw new BadRequestError('title is required', 'validation_error');
      }
      if (title.length > BLOG_TITLE_MAX_LENGTH) {
        throw new BadRequestError('title exceeds max length', 'validation_error');
      }
      if (!isNonEmptyString(content)) {
        throw new BadRequestError('content is required', 'validation_error');
      }

      const baseSlug = isNonEmptyString(slug) ? slugify(slug) : slugify(title);
      if (!baseSlug) {
        throw new BadRequestError('Unable to derive slug from title', 'validation_error');
      }

      let candidateSlug = baseSlug;
      const exists = await BlogPost.findOne({ slug: candidateSlug }, { _id: 1 }).lean();
      if (exists) {
        candidateSlug = `${baseSlug.slice(0, BLOG_SLUG_MAX_LENGTH - SLUG_SUFFIX_LEN - 1)}-${slugSuffix()}`;
      }

      const finalStatus = status === 'published' || status === 'draft' || status === 'archived'
        ? status
        : 'draft';

      const now = new Date();
      const doc = new BlogPost({
        slug: candidateSlug,
        title,
        content,
        excerpt: typeof excerpt === 'string' ? excerpt : '',
        coverImage: typeof coverImage === 'string' ? coverImage : '',
        tags: Array.isArray(tags) ? tags.filter((t) => typeof t === 'string') : [],
        authorId,
        status: finalStatus,
        publishedAt: finalStatus === 'published' ? now : null,
        createdAt: now,
        updatedAt: now,
      });

      try {
        await doc.save();
      } catch (err) {
        if (err?.code === 11000) {
          throw new ConflictError('Slug already exists', 'slug_conflict');
        }
        throw err;
      }

      return doc.toObject();
    },

    /**
     * Admin: partial update of an existing post by id.
     * Status transition `draft → published` stamps `publishedAt` when missing.
     * Allows changing slug; collisions return 409.
     * @param {{ id: string, changes: object }} input
     */
    async updatePost({ id, changes }) {
      if (!isNonEmptyString(id)) {
        throw new BadRequestError('id is required', 'validation_error');
      }
      const safe = changes && typeof changes === 'object' ? changes : {};
      const post = await BlogPost.findById(id);
      if (!post) throw new NotFoundError('Post not found', 'post_not_found');

      if (typeof safe.title === 'string') {
        if (safe.title.length > BLOG_TITLE_MAX_LENGTH) {
          throw new BadRequestError('title exceeds max length', 'validation_error');
        }
        post.title = safe.title;
      }
      if (typeof safe.content === 'string') post.content = safe.content;
      if (typeof safe.excerpt === 'string') post.excerpt = safe.excerpt;
      if (typeof safe.coverImage === 'string') post.coverImage = safe.coverImage;
      if (Array.isArray(safe.tags)) {
        post.tags = safe.tags.filter((t) => typeof t === 'string');
      }
      if (typeof safe.slug === 'string' && safe.slug.length > 0) {
        const next = slugify(safe.slug);
        if (!next) throw new BadRequestError('Invalid slug', 'validation_error');
        post.slug = next;
      }
      if (safe.status && ['draft', 'published', 'archived'].includes(safe.status)) {
        const wasPublished = post.status === 'published';
        post.status = safe.status;
        if (safe.status === 'published' && !wasPublished && !post.publishedAt) {
          post.publishedAt = new Date();
        }
      }
      post.updatedAt = new Date();

      try {
        await post.save();
      } catch (err) {
        if (err?.code === 11000) {
          throw new ConflictError('Slug already exists', 'slug_conflict');
        }
        throw err;
      }
      return post.toObject();
    },
  };
}

module.exports = { createBlogService, slugify };
