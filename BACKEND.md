# Echo Backend – Architecture & Developer Guide

## Overview

Echo Backend is a **DDD (Domain-Driven Design) architected** Node.js + Express + Socket.IO real-time chat server. It implements the **Signal Protocol** for end-to-end encryption and supports both direct messaging and group chat with **MLS (Messaging Layer Security)** support.

### Key Technologies
- **Runtime**: Node.js (Express, Socket.IO)
- **Database**: MongoDB (Mongoose ODM)
- **Auth**: JWT + bcryptjs
- **Documentation**: Swagger/OpenAPI (HTTP), JSDoc (modules)
- **Testing**: Node native test runner (`node --test`)

---

## Architecture Overview

The codebase follows **DDD principles** with strict separation of concerns:

```
server.js                          # Thin composition root (170 lines)
├── src/
│   ├── config/                   # Configuration loading
│   │   └── loadEnv.js
│   ├── shared/                   # Shared kernel (constants, utilities)
│   │   └── constants.js
│   ├── infrastructure/
│   │   └── persistence/mongoose/
│   │       ├── connect.js        # DB connection
│   │       └── models.js         # Mongoose schemas
│   ├── modules/
│   │   ├── auth/
│   │   │   └── application/authService.js
│   │   ├── opk/
│   │   │   └── domain/opkPolicy.js
│   │   └── calls/
│   │       └── application/callEventService.js
│   ├── interfaces/
│   │   ├── http/
│   │   │   ├── routes/health.route.js
│   │   │   └── swagger.js
│   │   └── socket/
│   │       ├── registerSocketHandlers.js
│   │       ├── handlers/
│   │       │   ├── auth.handlers.js
│   │       │   ├── presence.handlers.js
│   │       │   ├── opk.handlers.js
│   │       │   ├── directMessaging.handlers.js
│   │       │   ├── groups.handlers.js
│   │       │   ├── calls.handlers.js
│   │       │   └── contactsAccount.handlers.js
│   │       └── context/
│   │           ├── sequences.js
│   │           ├── opkLimiter.js
│   │           └── profilePictureStorage.js
│   └── docs/
│       └── openapi.js
├── test/                         # Node test suite
├── opkPolicy.js                  # Legacy compat wrapper
└── package.json
```

### Layer Definitions

| Layer | Purpose | Examples |
|-------|---------|----------|
| **Domain** | Core business logic, value objects, rules | `src/modules/opk/domain/opkPolicy.js` |
| **Application** | Use cases, orchestration, DTOs | `src/modules/auth/application/authService.js` |
| **Infrastructure** | DB, external services, persistence | `src/infrastructure/persistence/mongoose/*` |
| **Interfaces** | Socket.IO handlers, HTTP routes, adapters | `src/interfaces/socket/handlers/*`, `src/interfaces/http/routes/*` |
| **Config/Shared** | Cross-cutting constants, utilities | `src/config/*`, `src/shared/*` |

---

## Environment Setup

### 1. Prerequisites
```bash
node >= 18
npm >= 9
MongoDB (local or cloud, e.g., MongoDB Atlas)
```

### 2. Environment Variables
Create `.env` in the repo root:
```env
MONGO_URI=mongodb://localhost:27017/echo-dev
JWT_SECRET=your-secret-key-here
NODE_ENV=development
PORT=3001
```

Notes:
- `MONGO_URI` is the primary runtime variable.
- `MONGO_URI_SECRET` is supported as a fallback when `MONGO_URI` is missing.
- Runtime (non-test) fails fast if `JWT_SECRET` is missing.

For tests, optionally create `.env.test`:
```env
MONGO_URI_TEST=mongodb://localhost:27017/echo-test
JWT_SECRET=test-secret
```

### 3. Install & Run
```bash
npm install
npm start
# Server listens on http://localhost:3001
```

### 4. View API Docs
- **Swagger UI (versioned)**: http://localhost:3001/api/v1/docs
- **OpenAPI JSON (versioned)**: http://localhost:3001/api/v1/docs/openapi.json
- **Health Check (versioned)**: GET http://localhost:3001/api/v1/health
- **Legacy aliases (temporary compatibility)**:
  - http://localhost:3001/docs
  - http://localhost:3001/docs/openapi.json
  - GET http://localhost:3001/health

---

## HTTP REST API

All 27 documented endpoints are now functional REST routes (previously they returned `501 socket_only_endpoint`). They share semantics and validation with the equivalent Socket.IO events; clients can pick either transport.

### Surface

| Tag | Endpoints |
|---|---|
| Authentication | `POST /auth/register`, `POST /auth/login` |
| Users | `POST /users/search`, `GET /users/:userId`, `PUT /users/profile/update`, `GET /users/online`, `DELETE /users/account/delete` |
| Contacts | `POST /contacts/add-friend`, `POST /contacts/remove-friend` |
| Messages | `POST /messages/check`, `POST /messages/latest-number`, `POST /messages/mark-seen` |
| Groups | `POST /groups/create`, `GET /groups/list`, `GET /groups/:groupId`, `POST /groups/:groupId/add-member`, `POST /groups/:groupId/remove-member` |
| Calls | `POST /calls/initiate`, `POST /calls/accept`, `POST /calls/decline`, `POST /calls/end`, `POST /calls/media-state` |
| Keys | `POST /keys/signed-prekey`, `POST /keys/identity/x25519`, `POST /keys/identity/ed25519`, `POST /keys/bundle`, `POST /keys/opk/upload`, `GET /keys/opk/status` |

### Authentication

`POST /auth/register` and `POST /auth/login` are public. Every other endpoint requires `Authorization: Bearer <jwt>` where `<jwt>` is the token returned by `/auth/login`.

The middleware lives in `src/interfaces/http/middleware/auth.js` (`createAuthMiddleware({ jwt })`). It mirrors the Socket.IO `authenticate` flow (same `JWT_SECRET`, same expected payload `{ id, username }`).

### Realtime side-effects from REST

REST handlers can still emit Socket.IO events to connected clients (e.g. `messageSeenUpdate`, `friendAdded`, `incomingCall`) through the `socketNotifier` adapter (`src/interfaces/socket/notifier.js`). The notifier is injected into every application service so services stay framework-agnostic.

### Error contract

All error responses are JSON of the shape:

```json
{ "success": false, "error": "...", "code": "...", "details": "..." }
```

Errors are produced by typed exceptions in `src/shared/errors.js` (`BadRequestError`, `UnauthorizedError`, `ForbiddenError`, `NotFoundError`, `ConflictError`, `RateLimitError`). Application services throw these and routers translate them via `sendHttpError`.

### Smoke testing

`scripts/smoke.sh` exercises all endpoints against a running server. It registers two users, drives the full surface, and tears down. Returns non-zero on any unexpected status.

```bash
npm start &       # boot against your .env (Atlas or local)
bash scripts/smoke.sh
```

---

## Adding New HTTP Endpoints

### Step 1: Create Route File
Create `src/interfaces/http/routes/yourFeature.route.js`:

```javascript
const express = require('express');

/**
 * @typedef {object} YourFeatureResponse
 * @property {boolean} success
 * @property {object} data
 */

/**
 * @openapi
 * /your-endpoint:
 *   get:
 *     tags:
 *       - Your Feature
 *     summary: Fetch your feature
 *     description: Returns data for your feature.
 *     responses:
 *       200:
 *         description: Success
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/YourFeatureResponse'
 *       500:
 *         description: Internal error
 */
const yourFeatureRouter = express.Router();

yourFeatureRouter.get('/your-endpoint', async (req, res) => {
  try {
    res.json({ success: true, data: {} });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = { yourFeatureRouter };
```

### Step 2: Wire in server.js
```javascript
const { yourFeatureRouter } = require('./src/interfaces/http/routes/yourFeature.route');
// ...
app.use(yourFeatureRouter);
```

### Step 3: Swagger picks it up automatically
- Restart the server
- Visit http://localhost:3001/docs

---

## Adding New Socket.IO Events

### Step 1: Understand Handler Structure
Socket handlers are in `src/interfaces/socket/handlers/`. Each follows this pattern:

```javascript
/**
 * Registers Socket.IO handlers for [feature].
 * @param {object} deps - Injected dependencies
 * @param {*} deps.socket - Socket.IO socket instance
 * @param {*} deps.io - Socket.IO server
 * @param {Record<string,string>} deps.userSocketMap - User ID → socket ID map
 * @param {*} deps.User - Mongoose User model
 * @param {...} deps[otherDeps]
 */
function registerYourFeatureSocketHandlers(deps) {
  const { socket, io, userSocketMap, User } = deps;

  /**
   * @typedef {object} YourEventPayload
   * @property {string} data
   */

  /**
   * Emitted by client on 'yourEvent'.
   * @param {YourEventPayload} payload
   * @param {function} callback - Ack function: (response) => void
   */
  socket.on('yourEvent', async (payload, callback) => {
    try {
      // Your logic here
      callback({ success: true });
    } catch (err) {
      console.error('Error in yourEvent:', err);
      callback({ success: false, error: err.message });
    }
  });
}

module.exports = { registerYourFeatureSocketHandlers };
```

### Step 2: Add Handler Registration
Add to `src/interfaces/socket/registerSocketHandlers.js`:

```javascript
const { registerYourFeatureSocketHandlers } = require('./handlers/yourFeature.handlers');

function registerSocketHandlers(deps) {
  // ... existing handlers ...

  registerYourFeatureSocketHandlers({
    socket,
    io,
    userSocketMap,
    User,
    // pass any other needed dependencies
  });
}
```

### Step 3: Document Event Contract
Add JSDoc typedef comments in your handler file. Example:

```javascript
/**
 * @typedef {object} YourEventResponse
 * @property {boolean} success
 * @property {string} [error] - Error message if success is false
 * @property {*} [data] - Response data if success is true
 */
```

---

## Adding New Application Services

### Step 1: Create Service Module
Create `src/modules/yourFeature/application/yourService.js`:

```javascript
/**
 * Application service for your feature use cases.
 * @param {object} deps
 * @param {*} deps.Model - Mongoose model
 * @param {...} deps[otherDeps]
 */
function createYourService({ Model, otherDep }) {
  return {
    /**
     * Example use case.
     * @param {object} input
     * @returns {Promise<object>}
     */
    async doSomething(input) {
      // Implementation
      return { result: true };
    },
  };
}

module.exports = { createYourService };
```

### Step 2: Wire in server.js
```javascript
const { createYourService } = require('./src/modules/yourFeature/application/yourService');

const yourService = createYourService({ Model, otherDep });

// Pass to socket handlers or HTTP routes as needed
```

---

## Centralizing Constants

All configuration constants are in `src/shared/constants.js`. Examples:

```javascript
// OPK (One-Time Pre-Key) policy
const OPK_LOW_WATERMARK = 50;
const OPK_MAX_STORED = 500;

// CORS & origins
const CORS_ORIGINS = ['http://localhost:5173', 'https://chat-tuah-frontend.vercel.app'];

// Rate limiting
const RATE_LIMITS = {
  opkRequests: { max: 60, windowMs: 60_000 },
};
```

**Import in any file:**
```javascript
const { OPK_MAX_STORED, CORS_ORIGINS } = require('./src/shared/constants');
```

---

## Database Schema Overview

### Core Collections

| Model | Purpose |
|-------|---------|
| **User** | User profiles, credentials, keys |
| **Message** | Direct & group messages, call events |
| **MessageSequence** | Conversation replay attack prevention |
| **Group** | Group metadata |
| **GroupMember** | Group membership, roles |
| **GroupSequence** | Group message ordering |
| **Call** | Call records |
| **KeyPackage** | MLS key packages |
| **OpkRequestLog** | OPK request audit trail (TTL 30 days) |

### Adding a New Model
In `src/infrastructure/persistence/mongoose/models.js`:

```javascript
const mySchema = new mongoose.Schema({
  // fields
});

const MyModel = mongoose.models.MyModel || mongoose.model('MyModel', mySchema);
```

Export from `createModels()` function and wire into `server.js`.

---

## Testing

### Running Tests
```bash
# All tests
npm test

# Specific test file
node --test test/opkPolicy.test.js

# With test env vars
MONGO_URI_TEST=mongodb://localhost:27017/echo-test npm test
```

### Writing New Tests
```javascript
const test = require('node:test');
const assert = require('node:assert/strict');

test('my feature works', async () => {
  // Arrange
  // Act
  // Assert
  assert.equal(result, expected);
});
```

---

## Best Practices

### 1. JSDoc All Public APIs
```javascript
/**
 * Does something important.
 * @param {object} input
 * @param {string} input.id - User ID
 * @returns {Promise<boolean>}
 * @throws {Error} If ID is invalid
 */
async function doSomething(input) { }
```

### 2. Preserve Socket.IO Contracts
When modifying handlers, keep event names, payload schemas, and ack signatures unchanged (backward compatibility).

### 3. Use Dependency Injection
Pass dependencies as function arguments, not globals. Makes testing easier.

### 4. Separate Concerns
- **Domain**: Pure business logic, no I/O
- **Application**: Use cases, orchestration
- **Infrastructure**: DB, external APIs
- **Interfaces**: User-facing (HTTP, Socket.IO)

### 5. Keep server.js Thin
No business logic in `server.js`. It should only wire dependencies and call registrars.

---

## Common Tasks

### Debug a Socket Event
1. Add `console.log` in handler
2. Restart server
3. Trigger from client
4. Check terminal output

### Add Rate Limiting
Use `createOpkLimiterService()` pattern or implement rate-limit-by middleware in HTTP routes.

### Extend Authentication
Modify `src/modules/auth/application/authService.js` or add middleware to handlers/routes.

### Migrate MongoDB Collection
Use Mongoose migrations or direct MongoDB CLI commands. Document schema changes in this file.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `MONGO_URI` error | Set env var or create `.env` file |
| `JWT_SECRET` undefined | Add to `.env` |
| Swagger docs empty | Check that route files have `@openapi` JSDoc blocks |
| Socket events not received | Verify handler is registered in `registerSocketHandlers.js` |
| Tests fail with DB errors | Set `MONGO_URI_TEST` to a test DB |

---

## References

- [DDD Pattern](https://martinfowler.com/bliki/DomainDrivenDesign.html)
- [Signal Protocol](https://signal.org/docs/)
- [Socket.IO Docs](https://socket.io/docs/)
- [Mongoose Guide](https://mongoosejs.com/docs/guide.html)
- [Swagger/OpenAPI](https://swagger.io/specification/)
- [JSDoc Reference](https://jsdoc.app/)

---

## Support

For issues or questions:
1. Check `.env` and environment setup
2. Review BACKEND.md architecture section
3. Inspect handler JSDoc comments
4. Check test files for usage examples
