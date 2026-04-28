const swaggerUi = require('swagger-ui-express');
const { buildOpenApiSpec } = require('../../docs/openapi');

/**
 * Mounts Swagger UI and raw OpenAPI JSON for HTTP routes.
 */
function setupSwagger(app) {
  const spec = buildOpenApiSpec();
  app.get('/docs/openapi.json', (_req, res) => res.json(spec));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(spec));
}

module.exports = { setupSwagger };
