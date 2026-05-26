/**
 * @module modules/groups/application/groupsService
 *
 * Application service for group lifecycle and membership use cases used by
 * the HTTP layer. Mirrors the socket handlers in
 * `src/interfaces/socket/handlers/groups.handlers.js` but is transport
 * agnostic — it never touches `socket`/`io` directly and instead emits
 * through a `notifier` adapter.
 */

const { customAlphabet } = require('nanoid');
const {
  BadRequestError,
  NotFoundError,
  ForbiddenError,
  ConflictError,
} = require('../../../shared/errors');

const GROUP_ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const GROUP_ID_SIZE = 5;
const CREATE_RETRY_LIMIT = 5;

/**
 * @param {object} deps
 * @param {import('mongoose').Model} deps.Group
 * @param {import('mongoose').Model} deps.GroupMember
 * @param {import('mongoose').Model} [deps.GroupSequence]
 * @param {import('mongoose').Model} [deps.User]
 * @param {(groupId:string)=>Promise<*>} deps.ensureGroupSequence
 * @param {{ emitToUser: Function }} deps.notifier
 */
function createGroupsService({
  Group,
  GroupMember,
  GroupSequence,
  User,
  ensureGroupSequence,
  notifier,
} = {}) {
  if (!Group) throw new Error('createGroupsService requires Group model');
  if (!GroupMember) throw new Error('createGroupsService requires GroupMember model');
  if (typeof ensureGroupSequence !== 'function') {
    throw new Error('createGroupsService requires ensureGroupSequence()');
  }

  const safeNotify = (userId, event, payload) => {
    if (notifier && typeof notifier.emitToUser === 'function') {
      try { notifier.emitToUser(String(userId ?? ''), event, payload); } catch { /* noop */ }
    }
  };

  function requireUserId(userId) {
    const id = typeof userId === 'string' ? userId.trim() : String(userId ?? '').trim();
    if (!id) throw new BadRequestError('Missing authenticated user', 'validation_error');
    return id;
  }

  return {
    /**
     * Create a new group. Generates a 5-char alphanumeric `groupId`, creates
     * the Group document, the admin GroupMember + sequence, and inserts a
     * GroupMember row for each unique invitee. Emits `groupAdded` to every
     * member through the notifier.
     *
     * @param {object} input
     * @param {string} input.userId - Authenticated user (becomes admin)
     * @param {string} input.name - Group display name
     * @param {Array<string>} input.memberIds - Invitee user IDs
     * @param {boolean} [input.mlsEnabled=false]
     * @param {string} [input.cipherSuite]
     */
    async createGroup({ userId, name, memberIds, mlsEnabled, cipherSuite } = {}) {
      const authedUserId = requireUserId(userId);

      if (typeof name !== 'string' || name.trim().length === 0) {
        throw new BadRequestError('Group name is required', 'validation_error', 'name');
      }
      if (!Array.isArray(memberIds) || memberIds.length === 0) {
        throw new BadRequestError('At least one member is required', 'validation_error', 'memberIds');
      }

      const wantsMls = mlsEnabled === true;
      const normalizedCipherSuite = wantsMls
        ? (typeof cipherSuite === 'string' && cipherSuite.trim().length > 0
            ? cipherSuite.trim()
            : 'Echo-MLS-TreeKEM/X25519_AES256GCM_SHA256')
        : null;

      const normalizedMemberIds = [...new Set(
        memberIds.map((m) => String(m ?? '')).filter(Boolean)
      )].filter((id) => id !== authedUserId);

      if (normalizedMemberIds.length === 0) {
        throw new BadRequestError('At least one member is required', 'validation_error', 'memberIds');
      }

      const nanoid = customAlphabet(GROUP_ID_ALPHABET, GROUP_ID_SIZE);
      const nowIso = new Date().toISOString();
      let groupId = null;
      let lastError = null;

      try {
        for (let attempt = 0; attempt < CREATE_RETRY_LIMIT; attempt++) {
          const candidate = nanoid();
          try {
            await Group.create({
              groupId: candidate,
              name,
              createdBy: authedUserId,
              createdAt: new Date(),
              mlsEnabled: wantsMls,
              epoch: 0,
              cipherSuite: normalizedCipherSuite,
            });
            groupId = candidate;
            break;
          } catch (err) {
            if (err?.code === 11000) {
              lastError = err;
              continue;
            }
            throw err;
          }
        }

        if (!groupId) {
          throw new ConflictError('Failed to allocate group id', 'group_id_collision');
        }

        await ensureGroupSequence(groupId);

        await GroupMember.create({
          groupId,
          userId: authedUserId,
          role: 'admin',
          joinedAt: new Date(),
          leafIndex: 0,
          status: 'active',
        });

        for (const [index, memberId] of normalizedMemberIds.entries()) {
          await GroupMember.create({
            groupId,
            userId: memberId,
            role: 'member',
            joinedAt: new Date(),
            leafIndex: index + 1,
            status: 'active',
          });
          safeNotify(memberId, 'groupAdded', {
            groupId, name, addedByUserId: authedUserId, role: 'member', at: nowIso,
          });
        }

        safeNotify(authedUserId, 'groupAdded', {
          groupId, name, addedByUserId: authedUserId, role: 'admin', at: nowIso,
        });

        return {
          group: { groupId, name, mlsEnabled: wantsMls, epoch: 0, cipherSuite: normalizedCipherSuite },
          members: [
            { userId: authedUserId, leafIndex: 0 },
            ...normalizedMemberIds.map((id, index) => ({ userId: id, leafIndex: index + 1 })),
          ],
        };
      } catch (err) {
        if (groupId) {
          await Promise.allSettled([
            Group.deleteOne({ groupId }),
            GroupSequence ? GroupSequence.deleteOne({ groupId }) : Promise.resolve(),
            GroupMember.deleteMany({ groupId }),
          ]);
        }
        if (err?.status) throw err;
        const message = err?.message || lastError?.message || 'Error creating group';
        const wrapped = new Error(message);
        wrapped.cause = err;
        throw wrapped;
      }
    },

    /**
     * List groups the user is currently a member of.
     */
    async listMyGroups({ userId } = {}) {
      const authedUserId = requireUserId(userId);

      const memberships = await GroupMember.find({
        userId: authedUserId,
        status: { $ne: 'removed' },
      }).lean();
      const groupIds = memberships.map((m) => String(m.groupId)).filter(Boolean);
      const groups = groupIds.length > 0
        ? await Group.find({ groupId: { $in: groupIds } }).lean()
        : [];

      const groupById = new Map(groups.map((g) => [String(g.groupId), g]));
      const result = memberships.map((m) => {
        const g = groupById.get(String(m.groupId));
        if (!g) return null;
        return {
          groupId: g.groupId,
          name: g.name,
          role: m.role,
          joinedAt: m.joinedAt,
          createdAt: g.createdAt,
          createdBy: g.createdBy,
          mlsEnabled: g.mlsEnabled,
          epoch: g.epoch,
          cipherSuite: g.cipherSuite,
          leafIndex: m.leafIndex,
          status: m.status,
        };
      }).filter(Boolean);

      return { groups: result };
    },

    /**
     * Fetch group details (group, caller membership, full member list with
     * profile snapshot). Throws ForbiddenError when the caller is not a
     * member, NotFoundError when the group does not exist.
     */
    async getGroupDetails({ userId, groupId } = {}) {
      const authedUserId = requireUserId(userId);
      const groupIdStr = String(groupId ?? '').trim();
      if (!groupIdStr) {
        throw new BadRequestError('Invalid groupId', 'validation_error', 'groupId');
      }

      const [group, membership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: authedUserId }).lean(),
      ]);

      if (!group) throw new NotFoundError('Group not found', 'group_not_found');
      if (!membership || membership.status === 'removed') {
        throw new ForbiddenError('Not a group member', 'forbidden');
      }

      const members = await GroupMember.find({
        groupId: groupIdStr,
        status: { $ne: 'removed' },
      }).lean();
      const memberIds = members.map((m) => String(m.userId));
      const profiles = User
        ? await User.find({ id: { $in: memberIds } }, { id: 1, username: 1, profilePicture: 1 }).lean()
        : [];
      const profileById = new Map(profiles.map((p) => [String(p.id), p]));

      return {
        group: {
          groupId: group.groupId,
          name: group.name,
          createdBy: group.createdBy,
          createdAt: group.createdAt,
          mlsEnabled: group.mlsEnabled,
          epoch: group.epoch,
          cipherSuite: group.cipherSuite,
        },
        membership: {
          role: membership.role,
          joinedAt: membership.joinedAt,
          leafIndex: membership.leafIndex,
          status: membership.status,
        },
        members: members.map((m) => {
          const uid = String(m.userId);
          const p = profileById.get(uid);
          return {
            userId: uid,
            role: m.role,
            joinedAt: m.joinedAt,
            username: p?.username ?? null,
            profilePicture: p?.profilePicture ?? null,
            leafIndex: m.leafIndex,
            status: m.status,
          };
        }),
      };
    },

    /**
     * Add a new member to an existing group. Caller must be admin. Emits
     * `groupAdded` to the new member and `groupMemberAdded` to every other
     * existing member via the notifier.
     */
    async addMember({ userId, groupId, memberId } = {}) {
      const authedUserId = requireUserId(userId);
      const groupIdStr = String(groupId ?? '').trim();
      const memberIdStr = String(memberId ?? '').trim();

      if (!groupIdStr) {
        throw new BadRequestError('Invalid groupId', 'validation_error', 'groupId');
      }
      if (!memberIdStr) {
        throw new BadRequestError('Missing required field: memberId', 'validation_error', 'memberId');
      }

      const [group, callerMembership] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: authedUserId }).lean(),
      ]);
      if (!group) throw new NotFoundError('Group not found', 'group_not_found');
      if (!callerMembership || callerMembership.status === 'removed' || callerMembership.role !== 'admin') {
        throw new ForbiddenError('Only admins can add members', 'forbidden');
      }

      const existing = await GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean();
      if (existing) throw new ConflictError('User already a member', 'already_member');

      const existingMembers = await GroupMember.find(
        { groupId: groupIdStr, status: { $ne: 'removed' } },
        { leafIndex: 1 }
      ).lean();
      const maxLeafIndex = existingMembers.reduce(
        (max, member) => (Number.isInteger(member.leafIndex) && member.leafIndex > max ? member.leafIndex : max),
        -1,
      );
      const nextLeafIndex = maxLeafIndex + 1;

      await GroupMember.create({
        groupId: groupIdStr,
        userId: memberIdStr,
        role: 'member',
        joinedAt: new Date(),
        leafIndex: nextLeafIndex,
        status: 'active',
      });

      const nowIso = new Date().toISOString();
      safeNotify(memberIdStr, 'groupAdded', {
        groupId: groupIdStr,
        name: group.name,
        addedByUserId: authedUserId,
        role: 'member',
        at: nowIso,
      });

      // existingMembers above projected only leafIndex; refetch userIds for notification
      const peers = await GroupMember.find(
        { groupId: groupIdStr, userId: { $ne: memberIdStr } },
        { userId: 1 },
      ).lean();
      for (const peer of peers) {
        const peerId = String(peer.userId ?? '');
        if (!peerId) continue;
        safeNotify(peerId, 'groupMemberAdded', {
          groupId: groupIdStr,
          memberId: memberIdStr,
          addedByUserId: authedUserId,
          role: 'member',
          at: nowIso,
        });
      }

      return {
        groupId: groupIdStr,
        member: { userId: memberIdStr, role: 'member', leafIndex: nextLeafIndex },
      };
    },

    /**
     * Remove a member from a group. A user can always remove themselves;
     * otherwise the caller must be admin and the target must not be admin.
     * Emits `groupRemoved` to the removed user and `groupMemberRemoved` to
     * the remaining members.
     */
    async removeMember({ userId, groupId, memberId } = {}) {
      const authedUserId = requireUserId(userId);
      const groupIdStr = String(groupId ?? '').trim();
      const memberIdStr = String(memberId ?? '').trim();

      if (!groupIdStr) {
        throw new BadRequestError('Invalid groupId', 'validation_error', 'groupId');
      }
      if (!memberIdStr) {
        throw new BadRequestError('Missing required field: memberId', 'validation_error', 'memberId');
      }

      const [group, callerMembership, targetMembership, remover] = await Promise.all([
        Group.findOne({ groupId: groupIdStr }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: authedUserId }).lean(),
        GroupMember.findOne({ groupId: groupIdStr, userId: memberIdStr }).lean(),
        User ? User.findOne({ id: authedUserId }, { username: 1 }).lean() : Promise.resolve(null),
      ]);

      if (!group) throw new NotFoundError('Group not found', 'group_not_found');
      if (!callerMembership || callerMembership.status === 'removed') {
        throw new ForbiddenError('Not a group member', 'forbidden');
      }
      if (!targetMembership || targetMembership.status === 'removed') {
        throw new NotFoundError('User is not a member', 'not_a_member');
      }

      const isSelf = authedUserId === memberIdStr;
      const canRemove = isSelf
        || (callerMembership.role === 'admin' && (targetMembership.role !== 'admin' || isSelf));
      if (!canRemove) throw new ForbiddenError('Cannot remove this member', 'forbidden');

      await GroupMember.deleteOne({ groupId: groupIdStr, userId: memberIdStr });

      const nowIso = new Date().toISOString();
      safeNotify(memberIdStr, 'groupRemoved', {
        groupId: groupIdStr,
        memberId: memberIdStr,
        removedByUserId: authedUserId,
        removedByUsername: remover?.username ?? null,
        groupName: group.name,
        at: nowIso,
      });

      const peers = await GroupMember.find(
        { groupId: groupIdStr },
        { userId: 1 },
      ).lean();
      for (const peer of peers) {
        const peerId = String(peer.userId ?? '');
        if (!peerId || peerId === memberIdStr) continue;
        safeNotify(peerId, 'groupMemberRemoved', {
          groupId: groupIdStr,
          memberId: memberIdStr,
          removedByUserId: authedUserId,
          removedByUsername: remover?.username ?? null,
          groupName: group.name,
          at: nowIso,
        });
      }

      return { groupId: groupIdStr, removedMemberId: memberIdStr };
    },
  };
}

module.exports = { createGroupsService };
