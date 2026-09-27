const fs = require('fs');
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const env = require('../config/env');
const db = require('../services/databaseService');
const { exportSessionPcap } = require('../services/sessionExportService');
const {
  AnalysisNotFoundError,
  ForbiddenError,
  SessionNotFoundError,
  SourceFileNotFoundError,
} = require('../utils/errors');
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
    const search = req.query.search ? String(req.query.search).trim() : undefined;
    const date = req.query.date ? String(req.query.date).trim() : undefined;

    const options = { page, limit };
    if (search) options.search = search;
    if (date) options.date = date;

    const result = await db.getAnalysesByUser(userId, options);

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
      uploaded_at: analysis.created_at,
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
 * GET /api/analyses/:analysisId/sessions
 *
 * Get paginated, filtered, and sorted sessions for an analysis.
 */
async function getSessions(req, res, next) {
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

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 15));
    const search = req.query.search ? String(req.query.search).trim() : '';
    const protocol = req.query.protocol ? String(req.query.protocol).trim() : 'ALL';
    const encryption = req.query.encryption ? String(req.query.encryption).trim() : 'ALL';
    const risk = req.query.risk ? String(req.query.risk).trim() : 'ALL';
    const sortBy = req.query.sortBy ? String(req.query.sortBy).trim() : 'tcp_stream';
    const sortOrder = req.query.sortOrder ? String(req.query.sortOrder).trim() : 'ASC';

    const result = await db.getSessionsByAnalysis(analysisId, {
      page,
      limit,
      search,
      protocol,
      encryption,
      risk,
      sortBy,
      sortOrder,
    });

    res.json(result);
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

/**
 * Locate the source capture file on disk.
 */
function findSourceCaptureFile(analysisId, filename) {
  const uploadDir = path.resolve(env.UPLOAD_DIR);
  const candidates = [
    path.join(uploadDir, `${analysisId}.pcap`),
    path.join(uploadDir, `${analysisId}.pcapng`),
    path.join(uploadDir, `${analysisId}.cap`),
    path.resolve(__dirname, '../../../captures/validation', filename || ''),
    path.resolve(__dirname, '../../../../captures/validation', filename || ''),
    path.resolve('captures/validation', filename || ''),
  ];

  for (const cand of candidates) {
    if (cand && fs.existsSync(cand) && fs.statSync(cand).isFile()) {
      return cand;
    }
  }

  return null;
}

/**
 * GET /api/analyses/:analysisId/sessions/:sessionId/pcap
 *
 * Download exact original packets for an individual session in PCAP format.
 * Server-side authorization check prevents IDOR.
 */
async function downloadSessionPcap(req, res, next) {
  let tempExportPath = null;
  try {
    const userId = req.user.id;
    const { analysisId, sessionId } = req.params;

    // Authorization check
    const analysis = await db.getAnalysisById(analysisId, userId);
    if (!analysis) {
      throw new AnalysisNotFoundError();
    }
    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to access this session capture.');
    }

    // Fetch session
    const session = await db.getSessionByRef(analysisId, sessionId);
    if (!session) {
      throw new SessionNotFoundError();
    }

    if (session.tcp_stream === null || session.tcp_stream === undefined) {
      return res.status(400).json({
        status: 'error',
        error: {
          code: 'NO_TCP_STREAM',
          message: 'This session does not have an associated TCP stream.',
        },
      });
    }

    // Locate source file
    const sourcePath = findSourceCaptureFile(analysisId, analysis.filename);
    if (!sourcePath) {
      throw new SourceFileNotFoundError('The source capture file is no longer available on disk.');
    }

    // Generate isolated temporary export path
    tempExportPath = path.join(os.tmpdir(), `sms_session_${uuidv4()}.pcap`);

    // Extract exact packets
    const exportResult = await exportSessionPcap(sourcePath, session.tcp_stream, tempExportPath);

    const safeFilename = (analysis.filename || 'session').replace(/[^a-zA-Z0-9._-]/g, '_');
    const downloadName = `${safeFilename}_stream_${session.tcp_stream}.pcap`;

    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap');
    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('X-Wireshark-Filter', `tcp.stream == ${session.tcp_stream}`);
    res.setHeader('X-Packet-Count', String(exportResult.packet_count));
    res.setHeader('X-Source-SHA256', exportResult.source_pcap_sha256);
    res.setHeader('X-Session-Completeness', session.capture_completeness || 'UNKNOWN');

    const fileStream = fs.createReadStream(tempExportPath);

    fileStream.on('error', (err) => {
      logger.error('Stream error during session PCAP download', { error: err.message });
      if (tempExportPath && fs.existsSync(tempExportPath)) {
        try { fs.unlinkSync(tempExportPath); } catch (_) {}
      }
      next(err);
    });

    res.on('finish', () => {
      if (tempExportPath && fs.existsSync(tempExportPath)) {
        try { fs.unlinkSync(tempExportPath); } catch (_) {}
      }
    });

    res.on('close', () => {
      if (tempExportPath && fs.existsSync(tempExportPath)) {
        try { fs.unlinkSync(tempExportPath); } catch (_) {}
      }
    });

    fileStream.pipe(res);

  } catch (err) {
    if (tempExportPath && fs.existsSync(tempExportPath)) {
      try { fs.unlinkSync(tempExportPath); } catch (_) {}
    }
    next(err);
  }
}

/**
 * GET /api/analyses/:analysisId/sessions/:sessionId/provenance
 *
 * Get provenance metadata linking session evidence to source capture.
 */
async function getSessionProvenance(req, res, next) {
  try {
    const userId = req.user.id;
    const { analysisId, sessionId } = req.params;

    const analysis = await db.getAnalysisById(analysisId, userId);
    if (!analysis) {
      throw new AnalysisNotFoundError();
    }
    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to access this session.');
    }

    const session = await db.getSessionByRef(analysisId, sessionId);
    if (!session) {
      throw new SessionNotFoundError();
    }

    res.json({
      analysis_id: analysis.id,
      session_id: session.session_ref || session.db_id,
      tcp_stream: session.tcp_stream,
      source_pcap_filename: analysis.filename,
      source_pcap_sha256: analysis.sha256,
      completeness: session.capture_completeness || 'UNKNOWN',
      wireshark_filter: session.tcp_stream !== null && session.tcp_stream !== undefined
        ? `tcp.stream == ${session.tcp_stream}`
        : null,
      start_time: session.start_time,
      end_time: session.end_time,
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getAnalyses,
  getAnalysisById,
  getSessions,
  exportAnalysis,
  downloadSessionPcap,
  getSessionProvenance,
};
