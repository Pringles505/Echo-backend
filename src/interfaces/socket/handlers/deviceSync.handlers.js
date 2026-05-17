function registerDeviceSyncSocketHandlers({ socket, deviceSyncService }) {
  if (!deviceSyncService) return;

  socket.on('sync.createSession', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const result = await deviceSyncService.createSession(payload || {});
      ack({ success: true, ...result });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_create_failed', code: err?.code || 'sync_create_failed' });
    }
  });

  socket.on('sync.attachSource', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const session = await deviceSyncService.attachSource({
        sessionId: payload?.sessionId,
        sourceEphemeralPubKey: payload?.sourceEphemeralPubKey,
        sourceUserId: socket.user?.id,
        sourceDevice: payload?.sourceDevice || {},
      });
      ack({ success: true, session });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_attach_failed', code: err?.code || 'sync_attach_failed' });
    }
  });

  socket.on('sync.confirmSession', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const actor = payload?.actor === 'target' ? 'target' : 'source';
      const session = await deviceSyncService.confirmSession({
        sessionId: payload?.sessionId,
        actor,
        userId: actor === 'source' ? socket.user?.id : null,
        targetAccessToken: actor === 'target' ? payload?.targetAccessToken : null,
        targetDevice: payload?.targetDevice || {},
      });
      ack({ success: true, session });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_confirm_failed', code: err?.code || 'sync_confirm_failed' });
    }
  });

  socket.on('sync.transferChunk', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const session = await deviceSyncService.transferChunk({
        sessionId: payload?.sessionId,
        userId: socket.user?.id,
        chunk: payload?.chunk,
      });
      ack({ success: true, session });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_chunk_failed', code: err?.code || 'sync_chunk_failed' });
    }
  });

  socket.on('sync.complete', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const actor = payload?.actor === 'target' ? 'target' : 'source';
      const result = await deviceSyncService.complete({
        sessionId: payload?.sessionId,
        actor,
        userId: actor === 'source' ? socket.user?.id : null,
        targetAccessToken: actor === 'target' ? payload?.targetAccessToken : null,
        targetDevice: payload?.targetDevice || {},
      });
      ack({ success: true, ...result });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_complete_failed', code: err?.code || 'sync_complete_failed' });
    }
  });

  socket.on('sync.cancel', async (payload, callback) => {
    const ack = typeof callback === 'function' ? callback : () => {};
    try {
      const session = await deviceSyncService.cancel({
        sessionId: payload?.sessionId,
        userId: socket.user?.id || null,
        targetAccessToken: payload?.targetAccessToken || null,
      });
      ack({ success: true, session });
    } catch (err) {
      ack({ success: false, error: err?.message || 'sync_cancel_failed', code: err?.code || 'sync_cancel_failed' });
    }
  });
}

module.exports = { registerDeviceSyncSocketHandlers };
