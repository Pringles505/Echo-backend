# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## Unreleased

### Features

* **http:** implement 27 functional REST endpoints across auth, users, contacts, messages, groups, calls, and keys; previously HTTP routes returned `501 socket_only_endpoint` and only the Socket.IO transport was operational.
* **http:** introduce shared `requireAuth` / `optionalAuth` JWT middleware and a typed `HttpServiceError` error hierarchy consumed by every router.
* **http:** add `helmet` (security headers) and `express-rate-limit` (login/register/search/key-bundle limiters).
* **docs(openapi):** rebuild schemas with concrete `items`, response envelopes (`BadRequestResponse`, `ConflictResponse`, `RateLimitedResponse`), and structured group/key types (`GroupSummary`, `GroupDetailsResponse`, `KeyBundle`, `OPKItem`, `MediaStateRequest`, `DeleteAccountRequest`).
* **socket(notifier):** extract `createSocketNotifier` so application services emit realtime events without coupling to Socket.IO.

### Bug Fixes

* **security(account-delete):** require the user's password in the body before deleting the account; previously a stolen token was sufficient (SEC-002).
* **constants:** lower `JSON_LIMIT` from 50MB to 15MB (SEC-003).

### Tests

* 27 endpoints exercised live against MongoDB Atlas via `scripts/smoke.sh`.
* 170 automated tests (`node --test`) including the new `*Http.test.js` suites for every domain.

### 1.0.1 (2026-04-28)


### Bug Fixes

* **http:** return explicit socket-only and db error statuses ([0ec1f3b](https://github.com/echo-chat-protocol/echo-backend/commit/0ec1f3ba37c423fa3b28f1d628f149d7b7289be8))
