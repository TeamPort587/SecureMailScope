const express = require('express');
const router = express.Router();

/**
 * GET /api/health
 *
 * Public health check endpoint. No authentication required.
 */
router.get('/', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'gateway',
    version: '1.0.0',
  });
});

module.exports = router;
