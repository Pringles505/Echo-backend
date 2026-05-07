const path = require('path');
const swaggerJsdoc = require('swagger-jsdoc');

const OPERATION_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];

const PUBLIC_OPERATION_PATHS = new Set([
  '/auth/register',
  '/auth/login',
  '/health',
]);

function buildServers(serverUrl) {
  const normalized = typeof serverUrl === 'string' && serverUrl.trim() ? serverUrl.trim() : '/';
  if (normalized === '/') {
    return [{ url: '/', description: 'Legacy compatibility routes' }];
  }

  return [
    { url: normalized, description: 'Versioned API (recommended)' },
    { url: '/', description: 'Legacy compatibility routes (deprecated)' },
  ];
}

function applyDefaultSecurity(spec) {
  const paths = spec?.paths || {};
  for (const [routePath, pathItem] of Object.entries(paths)) {
    for (const method of OPERATION_METHODS) {
      const operation = pathItem?.[method];
      if (!operation) continue;
      if (operation.security) continue;
      if (PUBLIC_OPERATION_PATHS.has(routePath)) continue;
      operation.security = [{ bearerAuth: [] }];
    }
  }
}

function buildOpenApiSpec({ serverUrl = '/' } = {}) {
  const spec = swaggerJsdoc({
    definition: {
      openapi: '3.0.3',
      info: {
        title: 'Echo Backend API',
        description: [
          'HTTP REST surface for the Echo Backend.',
          'Real-time delivery (presence, message broadcasts, call signaling) is also exposed via Socket.IO.',
          'Endpoints below are functional REST endpoints. The Socket.IO event names mirror the resource semantics where applicable.',
        ].join('\n\n'),
        version: '1.2.0',
        contact: { name: 'Echo Backend Team' },
        license: { name: 'MIT', url: 'https://opensource.org/licenses/MIT' },
      },
      externalDocs: {
        description: 'Backend architecture and implementation notes',
        url: 'https://github.com/echo-chat-protocol/echo-backend/blob/main/BACKEND.md',
      },
      servers: buildServers(serverUrl),
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'JWT access token returned by POST /auth/login.',
          },
        },
        schemas: {
          // ----- Generic envelopes ------------------------------------------
          ErrorResponse: {
            type: 'object',
            required: ['success', 'error'],
            properties: {
              success: { type: 'boolean', enum: [false] },
              error: { type: 'string' },
              code: { type: 'string' },
              details: { type: 'string' },
            },
          },
          SuccessResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean', enum: [true] },
            },
          },
          HealthResponse: { type: 'string', example: 'OK' },

          // ----- Auth -------------------------------------------------------
          KeyBundle: {
            type: 'object',
            required: ['publicIdentityKeyX25519', 'publicIdentityKeyEd25519', 'publicSignedPreKey', 'oneTimePreKeys'],
            properties: {
              publicIdentityKeyX25519: { type: 'string', description: 'Base64 X25519 identity public key' },
              publicIdentityKeyEd25519: { type: 'string', description: 'Base64 Ed25519 identity public key' },
              publicSignedPreKey: {
                type: 'array',
                description: '[signedPreKey, signature] pair (both base64).',
                items: { type: 'string' },
                minItems: 2,
                maxItems: 2,
              },
              oneTimePreKeys: {
                type: 'array',
                description: 'Initial one-time pre-keys.',
                items: { $ref: '#/components/schemas/OPKItem' },
              },
            },
          },
          OPKItem: {
            type: 'object',
            required: ['opkId'],
            properties: {
              opkId: { type: 'string' },
              opkPub: { type: 'string', description: 'Base64 OPK public key' },
              publicKey: { type: 'string', description: 'Legacy alias for opkPub' },
            },
          },
          RegisterRequest: {
            type: 'object',
            required: ['username', 'password', 'keyBundle'],
            properties: {
              username: { type: 'string', minLength: 1 },
              password: { type: 'string', minLength: 1 },
              keyBundle: { $ref: '#/components/schemas/KeyBundle' },
              aboutme: { type: 'string' },
              profilePicture: { type: 'string', description: 'Base64 data URL' },
            },
          },
          RegisterResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              userId: { type: 'string' },
              error: { type: 'string' },
              code: { type: 'string' },
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
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              token: { type: 'string', description: 'JWT bearer token' },
              userId: { type: 'string' },
              error: { type: 'string' },
            },
          },

          // ----- Users / Contacts -------------------------------------------
          UserProfile: {
            type: 'object',
            properties: {
              id: { type: 'string' },
              username: { type: 'string' },
              aboutme: { type: 'string' },
              profilePicture: { type: 'string' },
              friends: { type: 'array', items: { type: 'string' } },
            },
          },
          SearchUserRequest: {
            type: 'object',
            required: ['searchTerm'],
            properties: {
              searchTerm: { type: 'string', minLength: 1 },
            },
          },
          UserResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              user: { $ref: '#/components/schemas/UserProfile' },
              error: { type: 'string' },
            },
          },
          UpdateUserRequest: {
            type: 'object',
            description: 'When `newPassword` is supplied, `oldPassword` is required.',
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
            required: ['success', 'onlineUsers'],
            properties: {
              success: { type: 'boolean' },
              onlineUsers: { type: 'array', items: { type: 'string' } },
            },
          },
          DeleteAccountRequest: {
            type: 'object',
            required: ['password'],
            properties: {
              password: { type: 'string' },
            },
          },
          FriendRequest: {
            type: 'object',
            required: ['friendId'],
            properties: {
              friendId: { type: 'string' },
            },
          },
          ContactResponse: { $ref: '#/components/schemas/SuccessResponse' },

          // ----- Messages ---------------------------------------------------
          TargetUserRequest: {
            type: 'object',
            required: ['targetUserId'],
            properties: {
              targetUserId: { type: 'string' },
            },
          },
          CheckMessagesResponse: {
            type: 'object',
            required: ['success', 'exists'],
            properties: {
              success: { type: 'boolean' },
              exists: { type: 'boolean' },
            },
          },
          LatestMessageNumberResponse: {
            type: 'object',
            required: ['success', 'messageNumber'],
            properties: {
              success: { type: 'boolean' },
              messageNumber: { type: 'integer', description: 'Last accepted message number, -1 if none' },
            },
          },

          // ----- Groups -----------------------------------------------------
          CreateGroupRequest: {
            type: 'object',
            required: ['name', 'memberIds'],
            properties: {
              name: { type: 'string', minLength: 1 },
              memberIds: { type: 'array', items: { type: 'string' }, minItems: 1 },
              mlsEnabled: { type: 'boolean', default: false },
              cipherSuite: { type: 'string' },
            },
          },
          GroupSummary: {
            type: 'object',
            properties: {
              groupId: { type: 'string' },
              name: { type: 'string' },
              role: { type: 'string', enum: ['admin', 'member'] },
              joinedAt: { type: 'string', format: 'date-time' },
              createdAt: { type: 'string', format: 'date-time' },
              createdBy: { type: 'string' },
              mlsEnabled: { type: 'boolean' },
              epoch: { type: 'integer' },
              cipherSuite: { type: 'string', nullable: true },
              leafIndex: { type: 'integer', nullable: true },
              status: { type: 'string', enum: ['active', 'removed'] },
            },
          },
          GroupMemberSummary: {
            type: 'object',
            properties: {
              userId: { type: 'string' },
              role: { type: 'string', enum: ['admin', 'member'] },
              joinedAt: { type: 'string', format: 'date-time' },
              username: { type: 'string', nullable: true },
              profilePicture: { type: 'string', nullable: true },
              leafIndex: { type: 'integer', nullable: true },
              status: { type: 'string', enum: ['active', 'removed'] },
            },
          },
          GroupResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              group: {
                type: 'object',
                properties: {
                  groupId: { type: 'string' },
                  name: { type: 'string' },
                  mlsEnabled: { type: 'boolean' },
                  epoch: { type: 'integer' },
                  cipherSuite: { type: 'string', nullable: true },
                },
              },
              members: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    userId: { type: 'string' },
                    leafIndex: { type: 'integer' },
                  },
                },
              },
              error: { type: 'string' },
            },
          },
          GroupsListResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              groups: { type: 'array', items: { $ref: '#/components/schemas/GroupSummary' } },
              error: { type: 'string' },
            },
          },
          GroupDetailsResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              group: {
                type: 'object',
                properties: {
                  groupId: { type: 'string' },
                  name: { type: 'string' },
                  createdBy: { type: 'string' },
                  createdAt: { type: 'string', format: 'date-time' },
                  mlsEnabled: { type: 'boolean' },
                  epoch: { type: 'integer' },
                  cipherSuite: { type: 'string', nullable: true },
                },
              },
              membership: {
                type: 'object',
                properties: {
                  role: { type: 'string', enum: ['admin', 'member'] },
                  joinedAt: { type: 'string', format: 'date-time' },
                  leafIndex: { type: 'integer', nullable: true },
                  status: { type: 'string', enum: ['active', 'removed'] },
                },
              },
              members: { type: 'array', items: { $ref: '#/components/schemas/GroupMemberSummary' } },
              error: { type: 'string' },
            },
          },
          GroupMemberMutationRequest: {
            type: 'object',
            required: ['memberId'],
            properties: {
              memberId: { type: 'string' },
            },
          },

          // ----- Calls ------------------------------------------------------
          InitiateCallRequest: {
            type: 'object',
            required: ['targetUserId', 'callId'],
            properties: {
              targetUserId: { type: 'string' },
              callId: { type: 'string' },
            },
          },
          CallIdRequest: {
            type: 'object',
            required: ['callId'],
            properties: { callId: { type: 'string' } },
          },
          MediaStateRequest: {
            type: 'object',
            required: ['targetUserId', 'mediaType', 'isEnabled'],
            properties: {
              targetUserId: { type: 'string' },
              mediaType: { type: 'string', enum: ['audio', 'video'] },
              isEnabled: { type: 'boolean' },
            },
          },
          CallResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              status: { type: 'string', enum: ['ringing', 'in-progress', 'declined', 'ended', 'missed'] },
              duration: { type: 'integer', description: 'Duration in seconds (only for ended calls)' },
              error: { type: 'string' },
              code: { type: 'string' },
            },
          },

          // ----- Keys / OPK -------------------------------------------------
          KeyBundleRequest: {
            type: 'object',
            required: ['targetUserId'],
            properties: { targetUserId: { type: 'string' } },
          },
          SignedPreKeyResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              signedPreKey: { type: 'string' },
              signature: { type: 'string' },
              spkId: { type: 'integer' },
              error: { type: 'string' },
            },
          },
          IdentityKeyResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              publicIdentityKeyX25519: { type: 'string' },
              publicIdentityKeyEd25519: { type: 'string' },
              error: { type: 'string' },
            },
          },
          PreKeyBundleResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              bundle: {
                type: 'object',
                properties: {
                  publicIdentityKeyX25519: { type: 'string' },
                  publicIdentityKeyEd25519: { type: 'string' },
                  signedPreKey: { type: 'string' },
                  signature: { type: 'string' },
                  spkId: { type: 'integer' },
                  opk: {
                    nullable: true,
                    type: 'object',
                    properties: {
                      opkId: { type: 'string' },
                      opkPub: { type: 'string' },
                    },
                  },
                },
              },
              error: { type: 'string' },
              retryAfterMs: { type: 'integer' },
            },
          },
          OPKUploadRequest: {
            type: 'object',
            required: ['oneTimePreKeys'],
            properties: {
              oneTimePreKeys: {
                type: 'array',
                items: { $ref: '#/components/schemas/OPKItem' },
              },
            },
          },
          OPKUploadResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              stored: { type: 'integer' },
              error: { type: 'string' },
            },
          },
          OPKStatusResponse: {
            type: 'object',
            required: ['success'],
            properties: {
              success: { type: 'boolean' },
              currentCount: { type: 'integer' },
              needed: { type: 'integer' },
              error: { type: 'string' },
            },
          },
        },
        responses: {
          HealthResponse: {
            description: 'Service is alive.',
            content: { 'text/plain': { schema: { $ref: '#/components/schemas/HealthResponse' } } },
          },
          BadRequestResponse: {
            description: 'Validation failed or input was malformed.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          UnauthorizedResponse: {
            description: 'Missing or invalid bearer token.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          ForbiddenResponse: {
            description: 'Authenticated user lacks permission for this resource.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          NotFoundResponse: {
            description: 'Resource not found.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          ConflictResponse: {
            description: 'Conflict with existing resource state (e.g. duplicate username).',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          RateLimitedResponse: {
            description: 'Too many requests in the current window.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          DatabaseUnavailableResponse: {
            description: 'Database connection is unavailable.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          InternalServerErrorResponse: {
            description: 'Unexpected server error.',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
      tags: [
        { name: 'Health', description: 'Service health and liveness.' },
        { name: 'Authentication', description: 'Account creation and login.' },
        { name: 'Users', description: 'User profile and account operations.' },
        { name: 'Contacts', description: 'Friend list management.' },
        { name: 'Messages', description: 'Direct message state queries.' },
        { name: 'Groups', description: 'Group management and MLS.' },
        { name: 'Calls', description: 'Voice/video call signaling.' },
        { name: 'Keys', description: 'Signal Protocol key material.' },
      ],
    },
    apis: [path.join(__dirname, '../interfaces/http/routes/**/*.js')],
  });

  applyDefaultSecurity(spec);
  return spec;
}

module.exports = { buildOpenApiSpec };
