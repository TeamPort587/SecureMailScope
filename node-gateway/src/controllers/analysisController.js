const db = require('../services/databaseService');
const { AnalysisNotFoundError, ForbiddenError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * GET /api/analyses
 *
 * List paginated analyses for the authenticated user.
 */
async function getAnalyses(req, res, next) {
  try {
    const userId = req.user.id;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));

    const result = await db.getAnalysesByUser(userId, { page, limit });

    res.json(result);
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/analyses/:analysisId
 *
 * Get a single analysis with full details.
 * Only the owning user can access their analyses.
 */
async function getAnalysisById(req, res, next) {
  try {
    const userId = req.user.id;
    const { analysisId } = req.params;

    const analysis = await db.getAnalysisById(analysisId, userId);

    if (!analysis) {
      throw new AnalysisNotFoundError();
    }

    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to view this analysis.');
    }

    const fullData = await db.getFullAnalysis(analysisId);

    // Build summary from stored counts
    const summary = {
      risk_label: analysis.overall_risk,
      risk_score: analysis.risk_score ? parseFloat(analysis.risk_score) : null,
      session_count: fullData.sessions.length,
      finding_count: fullData.findings.length,
    };

    res.json({
      analysis_id: analysis.id,
      status: analysis.status,
      filename: analysis.filename,
      sha256: analysis.sha256,
      file_size_bytes: parseInt(analysis.file_size_bytes, 10),
      analysis_version: analysis.analysis_version,
      created_at: analysis.created_at,
      completed_at: analysis.completed_at,
      error_code: analysis.error_code,
      error_message: analysis.error_message,

      summary,
      sessions: fullData.sessions,
      findings: fullData.findings,
      risk: fullData.risk,
      recommendations: fullData.recommendations,
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/analyses/:analysisId/export
 *
 * Export the complete stored analysis as JSON.
 */
async function exportAnalysis(req, res, next) {
  try {
    const userId = req.user.id;
    const { analysisId } = req.params;

    const analysis = await db.getAnalysisById(analysisId, userId);

    if (!analysis) {
      throw new AnalysisNotFoundError();
    }

    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to export this analysis.');
    }

    const fullData = await db.getFullAnalysis(analysisId);

    const exportData = {
      export_version: '1.0.0',
      exported_at: new Date().toISOString(),

      analysis: {
        analysis_id: analysis.id,
        status: analysis.status,
        filename: analysis.filename,
        sha256: analysis.sha256,
        file_size_bytes: parseInt(analysis.file_size_bytes, 10),
        analysis_version: analysis.analysis_version,
        overall_risk: analysis.overall_risk,
        risk_score: analysis.risk_score ? parseFloat(analysis.risk_score) : null,
        created_at: analysis.created_at,
        completed_at: analysis.completed_at,
      },

      sessions: fullData.sessions,
      findings: fullData.findings,
      risk: fullData.risk,
      recommendations: fullData.recommendations,
    };

    // Set content-disposition for download
    const safeFilename = analysis.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="analysis_${safeFilename}_${analysisId}.json"`
    );
    res.setHeader('Content-Type', 'application/json');

    res.json(exportData);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getAnalyses,
  getAnalysisById,
  exportAnalysis,
};
