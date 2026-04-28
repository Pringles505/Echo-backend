const mongoose = require('mongoose');

function hasDatabaseConnection() {
  return mongoose.connection.readyState === 1;
}

function respondSocketOnly(res) {
  try {
    if (!hasDatabaseConnection()) {
      return res.status(503).json({
        success: false,
        error: 'Database connection is not available',
      });
    }

    return res.status(501).json({
      success: false,
      error: 'This endpoint is only available via Socket.IO',
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err?.message || 'Unexpected server error',
    });
  }
}

module.exports = { respondSocketOnly };
