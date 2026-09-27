const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/auth');
const {
  getStatus,
  getSuggestions,
  chat,
} = require('../controllers/copilotController');

/**
 * GET /api/copilot/status
 * Check AI copilot availability and model status.
 */
router.get('/status', authenticate, getStatus);

/**
 * POST /api/copilot/suggestions
 * Generate context-aware suggested questions for an analysis.
 */
router.post('/suggestions', authenticate, getSuggestions);

/**
 * POST /api/copilot/chat
 * Chat with the AI copilot, grounded in analysis data.
 */
router.post('/chat', authenticate, chat);

module.exports = router;
