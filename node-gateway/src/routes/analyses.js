const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/auth');
const {
  getAnalyses,
  getAnalysisById,
  exportAnalysis,
} = require('../controllers/analysisController');

/**
 * GET /api/analyses
 * List paginated analyses for the authenticated user.
 */
router.get('/', authenticate, getAnalyses);

/**
 * GET /api/analyses/:analysisId
 * Get full analysis detail.
 */
router.get('/:analysisId', authenticate, getAnalysisById);

/**
 * GET /api/analyses/:analysisId/export
 * Export complete analysis as JSON.
 */
router.get('/:analysisId/export', authenticate, exportAnalysis);

module.exports = router;
