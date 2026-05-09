const test = require('node:test');
const assert = require('node:assert/strict');

const { buildOpenApiSpec } = require('../src/docs/openapi');

test('OpenAPI spec declares professional baseline components', () => {
  const spec = buildOpenApiSpec({ serverUrl: '/api/v1' });

  assert.equal(spec.openapi, '3.0.3');
  assert.ok(Array.isArray(spec.servers));
  assert.ok(spec.servers.some((server) => server.url === '/api/v1'));
  assert.ok(spec.servers.some((server) => server.url === '/'));

  const bearerAuth = spec.components?.securitySchemes?.bearerAuth;
  assert.ok(bearerAuth);
  assert.equal(bearerAuth.type, 'http');
  assert.equal(bearerAuth.scheme, 'bearer');
});

test('Public auth endpoints are not protected by default security', () => {
  const spec = buildOpenApiSpec({ serverUrl: '/api/v1' });
  const register = spec.paths?.['/auth/register']?.post;
  const login = spec.paths?.['/auth/login']?.post;

  const isPublic = (op) => !op.security || (Array.isArray(op.security) && op.security.length === 0);
  assert.ok(register, 'register operation present');
  assert.ok(login, 'login operation present');
  assert.ok(isPublic(register), 'register has no bearer security requirement');
  assert.ok(isPublic(login), 'login has no bearer security requirement');
});

test('Protected endpoints inherit default bearer security', () => {
  const spec = buildOpenApiSpec({ serverUrl: '/api/v1' });
  const opkStatus = spec.paths?.['/keys/opk/status']?.get;

  assert.ok(opkStatus, 'opk status operation present');
  assert.deepEqual(opkStatus.security, [{ bearerAuth: [] }]);
});

test('Health endpoint exposes plain HTTP discovery', () => {
  const spec = buildOpenApiSpec({ serverUrl: '/api/v1' });
  const health = spec.paths?.['/health']?.get;

  assert.ok(health, 'health operation present');
  assert.equal(health['x-transport'], undefined, 'health is no longer marked socket-only');
});

test('Critical schemas declare typed array items', () => {
  const spec = buildOpenApiSpec({ serverUrl: '/api/v1' });
  const schemas = spec.components.schemas;

  assert.ok(schemas.KeyBundle.properties.oneTimePreKeys.items, 'KeyBundle.oneTimePreKeys has items');
  assert.ok(schemas.OPKUploadRequest.properties.oneTimePreKeys.items, 'OPKUploadRequest.oneTimePreKeys has items');
  assert.ok(schemas.GroupsListResponse.properties.groups.items, 'GroupsListResponse.groups has items');
});
