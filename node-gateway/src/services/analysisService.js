const fs = require('fs');
const path = require('path');
const { calculateSHA256 } = require('../utils/hash');
const { analyzeFile } = require('./djangoClient');
const { validateDjangoResponse } = require('../validators/analysisSchema');
const db = require('./databaseService');
const logger = require('../utils/logger');
const {
  InvalidAnalysisResponseError,
  AnalysisFailedError,
} = require('../utils/errors');

/**
 * Main analysis orchestration.
 *
 * Flow:
 * 1. Calculate SHA-256
 * 2. Create analysis record (PROCESSING)
 * 3. Call Django
 * 4. Validate response
 * 5. Transform & persist in transaction
 * 6. Cleanup temp file
 * 7. Return result
 */
async function processUpload(userId, file) {
  const filePath = file.path;
  const originalFilename = file.originalname;
  const fileSize = file.size;
  let analysisId = null;

  try {
    // Step 1: SHA-256
    logger.info('Calculating SHA-256', { filename: originalFilename });
    const sha256 = await calculateSHA256(filePath);

    // Step 2: Create analysis record
    const analysis = await db.createAnalysis({
      userId,
      filename: originalFilename,
      sha256,
      fileSizeBytes: fileSize,
    });
    analysisId = analysis.id;
    logger.info('Analysis created', { analysisId, status: 'PROCESSING' });

    // Step 3: Call Django
    logger.info('Sending to Django for analysis', { analysisId });
    const djangoResponse = await analyzeFile(filePath, {
      analysis_id: analysisId,
      filename: originalFilename,
      sha256,
      size_bytes: fileSize,
    });

    // Step 4: Validate Django response
    const validation = validateDjangoResponse(djangoResponse);

    if (!validation.success) {
      logger.error('Django response validation failed', {
        analysisId,
        error: validation.error,
      });
      await db.failAnalysis(analysisId, 'INVALID_ANALYSIS_RESPONSE', validation.error);
      throw new InvalidAnalysisResponseError();
    }

    const validatedData = validation.data;

    // Step 5: Transform contract data → DB format
    const mappedData = transformForPersistence(validatedData);

    // Step 6: Persist in transaction
    await db.persistAnalysisResult(analysisId, mappedData);

    // Step 7: Cleanup temp file
    cleanupFile(filePath);

    // Step 8: Retrieve and return the complete stored analysis
    const storedAnalysis = await db.getAnalysisById(analysisId, userId);
    const fullData = await db.getFullAnalysis(analysisId);

    logger.info('Analysis completed', { analysisId });

    return formatAnalysisResponse(storedAnalysis, fullData, validatedData.summary);

  } catch (err) {
    // Cleanup temp file on error
    cleanupFile(filePath);

    // If analysis was created, mark it failed (unless already handled)
    if (analysisId && !err.errorCode?.includes('INVALID_ANALYSIS_RESPONSE')) {
      await db.failAnalysis(
        analysisId,
        err.errorCode || 'ANALYSIS_FAILED',
        err.message || 'The analysis could not be completed.'
      );
    }

    throw err;
  }
}

/**
 * Transform validated Django contract data into the normalized DB format.
 *
 * Maps contract field names → DB column names:
 *   client_ip → src_ip, server_ip → dst_ip
 *   Nested security/tls/certificate → flattened security_info
 *   risk.level → risk_label, risk.score → risk_score
 *   evidence → evidence_json
 */
function transformForPersistence(data) {
  // Map sessions
  const sessions = data.sessions.map((s) => ({
    session_ref: s.session_id,
    tcp_stream: null, // Not in contract
    protocol: s.protocol,
    service: s.service || null,
    service_port: s.server_port,
    src_ip: s.client_ip,
    src_port: s.client_port,
    dst_ip: s.server_ip,
    dst_port: s.server_port,
    encryption_mode: s.security.encryption_mode,
    capture_completeness: s.security.capture_completeness,
    risk_label: s.risk_label || null,
    start_time: null,
    end_time: null,

    // Flattened security_info
    security_info: {
      upgrade_advertised: s.security.upgrade_advertised,
      upgrade_requested: s.security.upgrade_requested,
      upgrade_succeeded: s.security.upgrade_succeeded,
      authentication_before_tls: s.security.authentication_before_tls,

      tls_version: s.tls?.version || null,
      cipher_suite: s.tls?.cipher_suite || null,
      key_exchange: null, // Not in contract
      pfs: s.tls?.pfs || null,

      certificate_visibility: s.certificate?.visibility || null,
      certificate_subject: s.certificate?.subject || null,
      certificate_issuer: s.certificate?.issuer || null,
      certificate_valid_from: s.certificate?.valid_from || null,
      certificate_valid_to: s.certificate?.valid_until || null,
      certificate_key_algorithm: s.certificate?.key_type || null,
      certificate_key_size: s.certificate?.key_size || null,
      self_signed: s.certificate?.self_signed ?? null,
    },
  }));

  // Map findings
  const findings = data.findings.map((f) => ({
    finding_ref: f.finding_id,
    session_ref: f.session_id,
    finding_type: f.finding_type,
    severity: f.severity,
    title: f.title,
    description: f.description,
    confidence: f.confidence,
    evidence_json: f.evidence,
  }));

  // Map risk
  const risk = data.risk
    ? {
        risk_label: data.risk.level,
        risk_score: data.risk.score,
        model_version: data.risk.model_version,
        method: data.risk.method || null,
        confidence: data.risk.confidence || null,
      }
    : null;

  // Map recommendations
  const recommendations = data.recommendations.map((r) => ({
    finding_ref: null, // Contract doesn't link recs to findings
    priority: r.priority,
    title: r.title,
    recommendation_text: r.description,
  }));

  return {
    analysis_version: data.analysis_version,
    sessions,
    findings,
    risk,
    recommendations,
  };
}

/**
 * Format the stored analysis into the API response shape.
 */
function formatAnalysisResponse(analysis, fullData, summary) {
  return {
    analysis_id: analysis.id,
    status: analysis.status,
    filename: analysis.filename,
    uploaded_at: analysis.created_at,
    summary: {
      total_sessions: summary.total_sessions,
      smtp_sessions: summary.smtp_sessions || 0,
      imap_sessions: summary.imap_sessions || 0,
      pop3_sessions: summary.pop3_sessions || 0,
      plaintext_sessions: summary.plaintext_sessions || 0,
      starttls_sessions: summary.starttls_sessions || 0,
      implicit_tls_sessions: summary.implicit_tls_sessions || 0,
      vulnerable_sessions: summary.vulnerable_sessions || 0,
      findings_count: summary.findings_count,
    },
    sessions: fullData.sessions,
    findings: fullData.findings,
    recommendations: fullData.recommendations,
  };
}

/**
 * Safely delete a temporary file.
 */
function cleanupFile(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      logger.debug('Cleaned up temporary file', { filePath });
    }
  } catch (err) {
    logger.warn('Failed to cleanup temporary file', {
      filePath,
      error: err.message,
    });
  }
}

module.exports = {
  processUpload,
  transformForPersistence,
};
