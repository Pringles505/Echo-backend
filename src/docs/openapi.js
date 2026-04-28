const path = require('path');
const swaggerJsdoc = require('swagger-jsdoc');

function buildOpenApiSpec() {
  return swaggerJsdoc({
    definition: {
      openapi: '3.0.3',
      info: {
        title: 'Echo Backend HTTP API',
        description: 'REST API for Echo real-time chat backend. Note: Authentication, messaging delivery, and call signaling primarily use Socket.IO. These endpoints are for service discovery and documentation.',
        version: '1.0.0',
        contact: {
          name: 'Echo Development',
        },
      },
      servers: [{ url: '/' }],
      components: {
        schemas: {
          RegisterRequest: {
            type: 'object',
            required: ['username', 'password', 'keyBundle'],
            properties: {
              username: { type: 'string' },
              password: { type: 'string' },
              keyBundle: { type: 'object' },
              aboutme: { type: 'string' },
              profilePicture: { type: 'string' },
            },
          },
          RegisterResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              userId: { type: 'string' },
              error: { type: 'string' },
            },
          },
          LoginRequest: {
            type: 'object',
            required: ['username', 'password'],
            properties: {
              username: { type: 'string' },
              password: { type: 'string' },
            },
          },
          LoginResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              token: { type: 'string' },
              userId: { type: 'string' },
              error: { type: 'string' },
            },
          },
          SearchUserRequest: {
            type: 'object',
            required: ['searchTerm'],
            properties: {
              searchTerm: { type: 'string' },
            },
          },
          UserProfile: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              username: { type: 'string' },
              aboutme: { type: 'string' },
              profilePicture: { type: 'string' },
            },
          },
          UserResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              user: { $ref: '#/components/schemas/UserProfile' },
              error: { type: 'string' },
            },
          },
          UpdateUserRequest: {
            type: 'object',
            properties: {
              username: { type: 'string' },
              aboutme: { type: 'string' },
              profilePicture: { type: 'string' },
              oldPassword: { type: 'string' },
              newPassword: { type: 'string' },
            },
          },
          OnlineUsersResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              onlineUsers: { type: 'array', items: { type: 'string' } },
              error: { type: 'string' },
            },
          },
          FriendRequest: {
            type: 'object',
            required: ['friendId'],
            properties: {
              friendId: { type: 'string' },
            },
          },
          ContactResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              error: { type: 'string' },
            },
          },
          CreateGroupRequest: {
            type: 'object',
            required: ['groupName', 'memberIds'],
            properties: {
              groupName: { type: 'string' },
              memberIds: { type: 'array', items: { type: 'string' } },
            },
          },
          GroupResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              groupId: { type: 'string' },
              error: { type: 'string' },
            },
          },
          GroupsListResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              groups: { type: 'array' },
              error: { type: 'string' },
            },
          },
          InitiateCallRequest: {
            type: 'object',
            required: ['targetUserId', 'callId'],
            properties: {
              targetUserId: { type: 'string' },
              callId: { type: 'string' },
            },
          },
          CallResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              error: { type: 'string' },
            },
          },
          KeyBundleRequest: {
            type: 'object',
            required: ['targetUserId'],
            properties: {
              targetUserId: { type: 'string' },
            },
          },
          KeyBundleResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              signedPreKey: { type: 'string' },
              signature: { type: 'string' },
              oneTimePreKeys: { type: 'array' },
              error: { type: 'string' },
            },
          },
          OPKUploadRequest: {
            type: 'object',
            required: ['oneTimePreKeys'],
            properties: {
              oneTimePreKeys: { type: 'array' },
            },
          },
          OPKResponse: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              count: { type: 'number' },
              error: { type: 'string' },
            },
          },
        },
      },
      tags: [
        {
          name: 'Health',
          description: 'Server health check',
        },
        {
          name: 'Authentication',
          description: 'User registration and login (primarily via Socket.IO)',
        },
        {
          name: 'Messages',
          description: 'Message state queries (actual messaging via Socket.IO)',
        },
        {
          name: 'Users',
          description: 'User profile and account management',
        },
        {
          name: 'Contacts',
          description: 'Friend and contact management',
        },
        {
          name: 'Groups',
          description: 'Group chat operations',
        },
        {
          name: 'Calls',
          description: 'Voice and video calling operations',
        },
        {
          name: 'Keys',
          description: 'Signal Protocol key management and OPK operations',
        },
      ],
    },
    apis: [path.join(__dirname, '../interfaces/http/routes/**/*.js')],
  });
}

module.exports = { buildOpenApiSpec };
