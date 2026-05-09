/**
 * @module interfaces/http/routes/groups
 * Group lifecycle and membership REST endpoints.
 *
 * Diverges from the socket equivalent for `GET /groups/:groupId`: the HTTP
 * endpoint never joins a Socket.IO room (room membership remains the
 * client's responsibility via the socket transport).
 */

const express = require('express');
const { validateBody, requireDatabase } = require('../middleware/validate');
const { sendHttpError } = require('../errors/httpErrorResponse');
const { createGroupsService } = require('../../../modules/groups/application/groupsService');

function resolveGroupsService(deps) {
  if (deps?.groupsService) return deps.groupsService;
  const models = deps?.models || {};
  const services = deps?.services || {};
  const sequenceService = services.sequenceService || {};
  return createGroupsService({
    Group: models.Group,
    GroupMember: models.GroupMember,
    GroupSequence: models.GroupSequence,
    User: models.User,
    ensureGroupSequence: sequenceService.ensureGroupSequence,
    notifier: deps?.notifier,
  });
}

/**
 * @param {object} deps
 * @param {object} [deps.groupsService] - Explicit service (preferred for tests)
 * @param {*} deps.mongoose
 * @param {import('express').RequestHandler} [deps.requireAuth]
 * @returns {import('express').Router}
 */
function createGroupsRouter(deps = {}) {
  const groupsService = resolveGroupsService(deps);
  const { mongoose, requireAuth } = deps;
  if (!mongoose) throw new Error('createGroupsRouter requires mongoose');

  const router = express.Router();
  const dbGuard = requireDatabase(mongoose);
  const authGuard = typeof requireAuth === 'function'
    ? requireAuth
    : (_req, _res, next) => next();

  function handleServiceError(res, err, next) {
    if (err?.status) {
      return sendHttpError(res, err.status, err.message, err.code, err.details);
    }
    return next(err);
  }

  /**
   * @openapi
   * /groups/create:
   *   post:
   *     tags: [Groups]
   *     summary: Create a new group
   *     description: |
   *       Creates a Group document, the admin GroupMember row and one
   *       GroupMember per invitee, then emits `groupAdded` to every member
   *       through the configured notifier.
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/CreateGroupRequest'
   *     responses:
   *       201:
   *         description: Group created
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/GroupResponse'
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/groups/create',
    authGuard,
    dbGuard,
    validateBody([
      { field: 'name', type: 'string' },
      { field: 'memberIds', type: 'array' },
      { field: 'mlsEnabled', type: 'boolean', required: false },
      { field: 'cipherSuite', type: 'string', required: false },
    ]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { name, memberIds, mlsEnabled, cipherSuite } = req.body;
        const result = await groupsService.createGroup({ userId, name, memberIds, mlsEnabled, cipherSuite });
        return res.status(201).json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /groups/list:
   *   get:
   *     tags: [Groups]
   *     summary: List groups the authenticated user belongs to
   *     responses:
   *       200:
   *         description: User's group list
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/GroupsListResponse'
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  // IMPORTANT: must be declared before '/groups/:groupId' so Express does
  // not match "list" as a groupId path parameter.
  router.get(
    '/groups/list',
    authGuard,
    dbGuard,
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { groups } = await groupsService.listMyGroups({ userId });
        return res.json({ success: true, groups });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /groups/{groupId}:
   *   get:
   *     tags: [Groups]
   *     summary: Get group details
   *     description: |
   *       Returns the group document, the caller's membership and a snapshot
   *       of all current members. Unlike the socket equivalent (`openGroup`),
   *       this endpoint never joins a Socket.IO room — room management stays
   *       with the socket transport.
   *     parameters:
   *       - in: path
   *         name: groupId
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       200:
   *         description: Group details
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/GroupDetailsResponse'
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.get(
    '/groups/:groupId',
    authGuard,
    dbGuard,
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { groupId } = req.params;
        const result = await groupsService.getGroupDetails({ userId, groupId });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /groups/{groupId}/add-member:
   *   post:
   *     tags: [Groups]
   *     summary: Add a member to a group (admin only)
   *     parameters:
   *       - in: path
   *         name: groupId
   *         required: true
   *         schema: { type: string }
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/GroupMemberMutationRequest'
   *     responses:
   *       200:
   *         description: Member added
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               required: [success]
   *               properties:
   *                 success: { type: boolean }
   *                 groupId: { type: string }
   *                 member:
   *                   type: object
   *                   properties:
   *                     userId: { type: string }
   *                     role: { type: string, enum: [admin, member] }
   *                     leafIndex: { type: integer }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       409: { $ref: '#/components/responses/ConflictResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/groups/:groupId/add-member',
    authGuard,
    dbGuard,
    validateBody([{ field: 'memberId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { groupId } = req.params;
        const { memberId } = req.body;
        const result = await groupsService.addMember({ userId, groupId, memberId });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  /**
   * @openapi
   * /groups/{groupId}/remove-member:
   *   post:
   *     tags: [Groups]
   *     summary: Remove a member from a group
   *     parameters:
   *       - in: path
   *         name: groupId
   *         required: true
   *         schema: { type: string }
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             $ref: '#/components/schemas/GroupMemberMutationRequest'
   *     responses:
   *       200:
   *         description: Member removed
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               required: [success]
   *               properties:
   *                 success: { type: boolean }
   *                 groupId: { type: string }
   *                 removedMemberId: { type: string }
   *       400: { $ref: '#/components/responses/BadRequestResponse' }
   *       401: { $ref: '#/components/responses/UnauthorizedResponse' }
   *       403: { $ref: '#/components/responses/ForbiddenResponse' }
   *       404: { $ref: '#/components/responses/NotFoundResponse' }
   *       503: { $ref: '#/components/responses/DatabaseUnavailableResponse' }
   */
  router.post(
    '/groups/:groupId/remove-member',
    authGuard,
    dbGuard,
    validateBody([{ field: 'memberId', type: 'string' }]),
    async (req, res, next) => {
      try {
        const userId = req.user?.id;
        const { groupId } = req.params;
        const { memberId } = req.body;
        const result = await groupsService.removeMember({ userId, groupId, memberId });
        return res.json({ success: true, ...result });
      } catch (err) {
        return handleServiceError(res, err, next);
      }
    }
  );

  return router;
}

module.exports = { createGroupsRouter };
