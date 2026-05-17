# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [1.2.1](https://github.com/echo-chat-protocol/echo-backend/compare/v1.2.0...v1.2.1) (2026-05-17)


### Bug Fixes

* **admin:** run dbGuard before requireAdmin so DB outage returns 503 ([96da315](https://github.com/echo-chat-protocol/echo-backend/commit/96da315a2e5d31002618f2cdb0aeed3f2e723260))
* **community:** atomic capacity reservation in registerForEvent ([5bcf465](https://github.com/echo-chat-protocol/echo-backend/commit/5bcf4659cc06972a1d0551383c24b8a8e6416725))
* **storage:** validate MIME + use async fs in banner and profile images ([feecee5](https://github.com/echo-chat-protocol/echo-backend/commit/feecee56880cb71cf2402e1ff04575cf69ae3770))

## [1.2.0](https://github.com/echo-chat-protocol/echo-backend/compare/v1.1.1...v1.2.0) (2026-05-17)


### Features

* **api:** add community, blog, admin, support, status endpoints + profile banner ([0db24a5](https://github.com/echo-chat-protocol/echo-backend/commit/0db24a55c1ed67211135507372b2dfcc5e2dfac8))
* **auth:** refresh token rotation with reuse detection ([d14a7ee](https://github.com/echo-chat-protocol/echo-backend/commit/d14a7ee4bbda98c468a0aea2551ffe906ed45867))

### 1.1.1 (2026-05-09)


### Bug Fixes

* add missing deps ([aeb4c47](https://github.com/echo-chat-protocol/echo-backend/commit/aeb4c470e818c1f4c15dcb98bed2ec5b88ef9221))

## [1.1.0](https://github.com/echo-chat-protocol/echo-backend/compare/v1.0.1...v1.1.0) (2026-05-07)


### Features

* **http/auth:** functional REST register + login ([53cab18](https://github.com/echo-chat-protocol/echo-backend/commit/53cab18b277890bcbad9d220f80ec31628385281))
* **http/calls:** functional call lifecycle + media-state endpoints ([ff47368](https://github.com/echo-chat-protocol/echo-backend/commit/ff47368d04d468f45363356331ef9a2b8e89cc65))
* **http/keys:** functional Signal Protocol pre-key + OPK endpoints ([863c31e](https://github.com/echo-chat-protocol/echo-backend/commit/863c31e8396221dd93144dd4b7a7320cf989e9ab))
* **http/messages-groups:** functional messages + groups endpoints ([937f700](https://github.com/echo-chat-protocol/echo-backend/commit/937f7004cf8565b5996fb50647e73a16f59d0b59))
* **http/users-contacts:** functional users + contacts endpoints (SEC-002) ([da862a0](https://github.com/echo-chat-protocol/echo-backend/commit/da862a0e9357218b9f65d2d0350d641062efbe9c))
* **http:** add HTTP platform layer (auth, validate, rate limit, notifier) ([3b10eca](https://github.com/echo-chat-protocol/echo-backend/commit/3b10ecaca6421c840302f0a2d2ed077e4e67ad42))
* **openapi:** rebuild schemas with typed responses and concrete items ([7b04fc7](https://github.com/echo-chat-protocol/echo-backend/commit/7b04fc76f7b365ffd6330321b0606b603162f529))

### 1.0.1 (2026-04-28)


### Bug Fixes

* **http:** return explicit socket-only and db error statuses ([0ec1f3b](https://github.com/echo-chat-protocol/echo-backend/commit/0ec1f3ba37c423fa3b28f1d628f149d7b7289be8))
