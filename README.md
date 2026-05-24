<h1 align="center">
  <picture>
    <source
      srcset="logoTextDark.png"
      media="(prefers-color-scheme: dark)"
      width="300"
      height="130"
    >
    <img
      src="logoTextLight.png"
      alt="Echo Logo"
      width="300"
      height="130"
    >
  </picture>
</h1>

# Echo Backend

Production-oriented backend service for Echo real-time messaging, built with **Node.js**, **Express**, **Socket.IO**, and **MongoDB**.

## Core Capabilities

- JWT-based authentication
- Direct and group messaging
- Call signaling and call-state events
- Signal/MLS key management
- Versioned HTTP API surface (`/api/v1`)
- Structured error contracts for HTTP and Socket.IO acknowledgements

## Runtime API Surface

### Versioned endpoints (official)

- `GET /api/v1/health`
- `GET /api/v1/docs`
- `GET /api/v1/docs/openapi.json`

### Legacy compatibility endpoints

- `GET /health`
- `GET /docs`
- `GET /docs/openapi.json`

Versioned responses include header: `X-API-Version: v1`.

## Requirements

- Node.js 18+ (20+ recommended)
- npm 9+
- MongoDB (local or Atlas)

## Environment Configuration

Create `.env` in the project root:

```env
MONGO_URI=mongodb://127.0.0.1:27017/echo_dev
JWT_SECRET=replace-with-a-long-random-secret
PORT=3001
NODE_ENV=development
```

Notes:

- `MONGO_URI` is the primary runtime variable.
- `MONGO_URI_SECRET` is accepted as a fallback when `MONGO_URI` is not set.
- In non-test runtime, startup fails fast if `JWT_SECRET` is missing.

Optional `.env.test`:

```env
MONGO_URI_TEST=mongodb://127.0.0.1:27017/echo_test
JWT_SECRET=test-secret
```

## Local Development

```bash
npm install
npm start
```

Default server URL: `http://localhost:3001`

## Testing

```bash
npm test
```

The repository uses `node --test` and includes coverage for:

- HTTP socket-only status/error behavior
- API versioned route behavior
- group/direct messaging flows
- call event acknowledgement contracts
- bootstrap auth flow from an empty database

## Error Contracts

### HTTP

Standard error payload:

```json
{
  "success": false,
  "error": "Human-readable message",
  "code": "stable_machine_code",
  "details": "optional_non_production_detail"
}
```

### Socket.IO ack

Success:

```json
{ "success": true }
```

Failure:

```json
{ "success": false, "error": "message", "code": "stable_machine_code" }
```

## Security Notes

- Do not commit real secrets.
- Use separate credentials/databases per environment.
- Rotate `JWT_SECRET` and database credentials in deployed environments.

## License

MIT
