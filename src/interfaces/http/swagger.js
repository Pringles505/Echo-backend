const swaggerUi = require('swagger-ui-express');
const { buildOpenApiSpec } = require('../../docs/openapi');

/**
 * Mounts Swagger UI and raw OpenAPI JSON for HTTP routes.
 */
function setupSwagger(app, { basePath = '', includeLegacy = false } = {}) {
  const normalizedBasePath = basePath.endsWith('/')
    ? basePath.slice(0, -1)
    : basePath;
  const docsPath = `${normalizedBasePath}/docs` || '/docs';
  const openApiPath = `${docsPath}/openapi.json`;
  const spec = buildOpenApiSpec({ serverUrl: normalizedBasePath || '/' });

  app.get(openApiPath, (_req, res) => res.json(spec));
  app.use(docsPath, swaggerUi.serve, swaggerUi.setup(spec));

  if (includeLegacy && docsPath !== '/docs') {
    app.get('/docs/openapi.json', (_req, res) => res.json(spec));
    app.use('/docs', swaggerUi.serve, swaggerUi.setup(spec));
  }
}

module.exports = { setupSwagger };
