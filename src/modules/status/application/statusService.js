/**
 * @module modules/status/application/statusService
 *
 * Public health snapshot for the frontend. Reports:
 *  - mongo: 'up' | 'down' (uses mongoose admin ping when readyState=1)
 *  - uptime: process.uptime() in seconds
 *  - socketConnections: Socket.IO engine clientsCount, if available
 *  - timestamp: ISO8601
 *  - services[]: per-service entries for richer rendering in the frontend
 */

function createStatusService({ mongoose, io } = {}) {
  if (!mongoose) throw new Error('createStatusService requires mongoose');

  async function probeMongo() {
    const started = Date.now();
    if (mongoose.connection?.readyState !== 1) {
      return { name: 'mongodb', status: 'down', latencyMs: null };
    }
    try {
      if (mongoose.connection.db && typeof mongoose.connection.db.admin === 'function') {
        await mongoose.connection.db.admin().ping();
      }
      return { name: 'mongodb', status: 'up', latencyMs: Date.now() - started };
    } catch (_err) {
      return { name: 'mongodb', status: 'degraded', latencyMs: Date.now() - started };
    }
  }

  function probeSocket() {
    if (!io || !io.engine) {
      return { name: 'socket.io', status: 'down', connections: 0 };
    }
    const connections = typeof io.engine.clientsCount === 'number'
      ? io.engine.clientsCount
      : 0;
    return { name: 'socket.io', status: 'up', connections };
  }

  return {
    async getServicesStatus() {
      const [mongo, socket] = await Promise.all([
        probeMongo(),
        Promise.resolve(probeSocket()),
      ]);
      const services = [mongo, socket];
      const overall = services.every((s) => s.status === 'up') ? 'ok' : 'degraded';
      return {
        overall,
        uptime: Math.round(process.uptime()),
        timestamp: new Date().toISOString(),
        services,
      };
    },
  };
}

module.exports = { createStatusService };
