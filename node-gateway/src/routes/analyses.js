const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/auth');
const {
  getAnalyses,
  getAnalysisById,
  getSessions,
  exportAnalysis,
  downloadSessionPcap,
  getSessionProvenance,
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
 * GET /api/analyses/:analysisId/sessions
 * List paginated, filtered, and sorted sessions for an analysis.
 */
router.get('/:analysisId/sessions', authenticate, getSessions);

/**
 * GET /api/analyses/:analysisId/export
 * Export complete analysis as JSON.
 */
router.get('/:analysisId/export', authenticate, exportAnalysis);

/**
 * GET /api/analyses/:analysisId/sessions/:sessionId/pcap
 * Download exact original packets for an individual session in PCAP format.
 */
router.get('/:analysisId/sessions/:sessionId/pcap', authenticate, downloadSessionPcap);

/**
 * GET /api/analyses/:analysisId/sessions/:sessionId/provenance
 * Get evidence provenance metadata linking session to source capture.
 */
router.get('/:analysisId/sessions/:sessionId/provenance', authenticate, getSessionProvenance);

module.exports = router;

