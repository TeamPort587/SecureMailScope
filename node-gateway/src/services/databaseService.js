const { pool } = require('../config/database');
const { DatabaseError } = require('../utils/errors');
const logger = require('../utils/logger');

// ==============================================================================
// USER OPERATIONS
// ==============================================================================

/**
 * Create a new user.
 * @param {string} email
 * @param {string} passwordHash
 * @returns {Promise<{id: string, email: string, created_at: string}>}
 */
async function createUser(email, passwordHash) {
  try {
    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email, created_at`,
      [email, passwordHash]
    );
    return result.rows[0];
  } catch (err) {
    if (err.code === '23505') {
      // Unique violation — duplicate email
      throw err; // Let controller handle this specifically
    }
    logger.error('Database error creating user', { error: err.message, code: err.code, detail: err.detail });
throw new DatabaseError();
  }
}

/**
 * Find user by email.
 * @param {string} email
 * @returns {Promise<{id: string, email: string, password_hash: string} | null>}
 */
async function findUserByEmail(email) {
  try {
    const result = await pool.query(
      'SELECT id, email, password_hash FROM users WHERE email = $1',
      [email]
    );
    return result.rows[0] || null;
  } catch (err) {
    logger.error('Database error finding user', { error: err.message });
    throw new DatabaseError();
  }
}

// ==============================================================================
// ANALYSIS OPERATIONS
// ==============================================================================

/**
 * Create a new analysis record with PROCESSING status.
 * @returns {Promise<{id: string}>}
 */
async function createAnalysis({ userId, filename, sha256, fileSizeBytes }) {
    console.error('=== createAnalysis CALLED ===');
  console.error('userId:', userId);
  console.error('filename:', filename);
  console.error('userIdType:', typeof userId);
  console.error('userIdValid:', /^[0-9a-f-]{36}$/.test(userId));
  console.error('DB config:', { host: process.env.DB_HOST, port: process.env.DB_PORT, database: process.env.DB_NAME, user: process.env.DB_USER });
  console.error('userId:', userId);
  console.error('filename:', filename);
  try {
    const result = await pool.query(
      `INSERT INTO analyses (user_id, filename, sha256, file_size_bytes, status)
       VALUES ($1, $2, $3, $4, 'PROCESSING')
       RETURNING id, created_at`,
      [userId, filename, sha256, fileSizeBytes]
    );
    return result.rows[0];
  } catch (err) {
    console.error('=== createAnalysis ERROR ===');
    console.error('message:', err.message);
    console.error('code:', err.code);
    console.error('detail:', err.detail);
    console.error('constraint:', err.constraint);
    console.error('table:', err.table);
    console.error('column:', err.column);
    console.error('===========================');
    throw new DatabaseError();
  }
}

/**
 * Update analysis status (COMPLETED or FAILED).
 */
async function updateAnalysisStatus(client, analysisId, {
  status,
  analysisVersion = null,
  overallRisk = null,
  riskScore = null,
  completedAt = null,
  errorCode = null,
  errorMessage = null,
}) {
  const queryClient = client || pool;
  await queryClient.query(
    `UPDATE analyses
     SET status = $1,
         analysis_version = $2,
         overall_risk = $3,
         risk_score = $4,
         completed_at = $5,
         error_code = $6,
         error_message = $7
     WHERE id = $8`,
    [status, analysisVersion, overallRisk, riskScore, completedAt, errorCode, errorMessage, analysisId]
  );
}

/**
 * Mark an analysis as FAILED (standalone, outside transaction).
 */
async function failAnalysis(analysisId, errorCode, errorMessage) {
  try {
    await pool.query(
      `UPDATE analyses
       SET status = 'FAILED',
           error_code = $1,
           error_message = $2,
           completed_at = NOW()
       WHERE id = $3`,
      [errorCode, errorMessage, analysisId]
    );
  } catch (err) {
    logger.error('Database error marking analysis as failed', { error: err.message });
  }
}

// ==============================================================================
// TRANSACTIONAL PERSISTENCE — persist complete analysis result
// ==============================================================================

/**
 * Persist the complete validated analysis result in a single transaction.
 *
 * @param {string} analysisId
 * @param {object} data — validated & mapped analysis data
 * @returns {Promise<void>}
 */
async function persistAnalysisResult(analysisId, data) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // -- Sessions + Security Info -----------------------------------------------
    const sessionIdMap = {}; // maps Django session_ref → DB UUID

    for (const session of data.sessions) {
      const sessionResult = await client.query(
        `INSERT INTO sessions
           (analysis_id, session_ref, tcp_stream, protocol, service, service_port,
            src_ip, src_port, dst_ip, dst_port,
            encryption_mode, capture_completeness, risk_label,
            start_time, end_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING id`,
        [
          analysisId,
          session.session_ref,
          session.tcp_stream,
          session.protocol,
          session.service,
          session.service_port,
          session.src_ip,
          session.src_port,
          session.dst_ip,
          session.dst_port,
          session.encryption_mode,
          session.capture_completeness,
          session.risk_label,
          session.start_time || null,
          session.end_time || null,
        ]
      );

      const dbSessionId = sessionResult.rows[0].id;
      sessionIdMap[session.session_ref] = dbSessionId;

      // Insert security_info (1:1)
      const si = session.security_info;
      await client.query(
        `INSERT INTO security_info
           (session_id,
            upgrade_advertised, upgrade_requested, upgrade_succeeded,
            authentication_before_tls,
            tls_version, cipher_suite, key_exchange, pfs,
            certificate_visibility, certificate_subject, certificate_issuer,
            certificate_valid_from, certificate_valid_to,
            certificate_key_algorithm, certificate_key_size, self_signed)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [
          dbSessionId,
          si.upgrade_advertised,
          si.upgrade_requested,
          si.upgrade_succeeded,
          si.authentication_before_tls,
          si.tls_version,
          si.cipher_suite,
          si.key_exchange,
          si.pfs,
          si.certificate_visibility,
          si.certificate_subject,
          si.certificate_issuer,
          si.certificate_valid_from,
          si.certificate_valid_to,
          si.certificate_key_algorithm,
          si.certificate_key_size,
          si.self_signed,
        ]
      );
    }

    // -- Findings ---------------------------------------------------------------
    const findingIdMap = {}; // maps Django finding_ref → DB UUID

    for (const finding of data.findings) {
      const sessionDbId = finding.session_ref
        ? sessionIdMap[finding.session_ref] || null
        : null;

      const findingResult = await client.query(
        `INSERT INTO findings
           (analysis_id, session_id, finding_type, severity,
            title, description, confidence, evidence_json)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING id`,
        [
          analysisId,
          sessionDbId,
          finding.finding_type,
          finding.severity,
          finding.title,
          finding.description,
          finding.confidence,
          JSON.stringify(finding.evidence_json),
        ]
      );

      findingIdMap[finding.finding_ref] = findingResult.rows[0].id;
    }

    // -- Risk Result ------------------------------------------------------------
    if (data.risk) {
      await client.query(
        `INSERT INTO risk_results
           (analysis_id, risk_label, risk_score, model_version, method, confidence)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [
          analysisId,
          data.risk.risk_label,
          data.risk.risk_score,
          data.risk.model_version,
          data.risk.method || null,
          data.risk.confidence || null,
        ]
      );
    }

    // -- Recommendations --------------------------------------------------------
    for (const rec of data.recommendations) {
      const findingDbId = rec.finding_ref
        ? findingIdMap[rec.finding_ref] || null
        : null;

      await client.query(
        `INSERT INTO recommendations
           (analysis_id, finding_id, priority, title, recommendation_text)
         VALUES ($1,$2,$3,$4,$5)`,
        [
          analysisId,
          findingDbId,
          rec.priority,
          rec.title || null,
          rec.recommendation_text,
        ]
      );
    }

    // -- Update analysis status -------------------------------------------------
    await updateAnalysisStatus(client, analysisId, {
      status: 'COMPLETED',
      analysisVersion: data.analysis_version,
      overallRisk: data.risk?.risk_label || null,
      riskScore: data.risk?.risk_score || null,
      completedAt: new Date().toISOString(),
    });

    await client.query('COMMIT');
    logger.info('Analysis persisted successfully', { analysisId });

  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Transaction rollback during analysis persistence', {
      analysisId,
      error: err.message,
    });
    throw new DatabaseError('Failed to persist analysis results.');
  } finally {
    client.release();
  }
}

// ==============================================================================
// RETRIEVAL OPERATIONS
// ==============================================================================

/**
 * Get paginated analyses for a user.
 */
async function getAnalysesByUser(userId, { page = 1, limit = 20 } = {}) {
  const offset = (page - 1) * limit;

  try {
    const countResult = await pool.query(
      'SELECT COUNT(*) FROM analyses WHERE user_id = $1',
      [userId]
    );
    const total = parseInt(countResult.rows[0].count, 10);

    const result = await pool.query(
      `SELECT
         a.id AS analysis_id,
         a.filename,
         a.status,
         a.overall_risk AS risk_label,
         a.risk_score,
         a.created_at,
         a.completed_at,
         a.error_code,
         a.error_message,
         (SELECT COUNT(*) FROM sessions s WHERE s.analysis_id = a.id) AS session_count,
         (SELECT COUNT(*) FROM findings f WHERE f.analysis_id = a.id) AS finding_count
       FROM analyses a
       WHERE a.user_id = $1
       ORDER BY a.created_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    );

    return {
      items: result.rows.map((row) => ({
        analysis_id: row.analysis_id,
        filename: row.filename,
        status: row.status,
        risk_label: row.risk_label,
        risk_score: row.risk_score ? parseFloat(row.risk_score) : null,
        session_count: parseInt(row.session_count, 10),
        finding_count: parseInt(row.finding_count, 10),
        created_at: row.created_at,
        completed_at: row.completed_at,
        error_code: row.error_code,
        error_message: row.error_message,
      })),
      pagination: {
        page,
        limit,
        total,
      },
    };
  } catch (err) {
    logger.error('Database error fetching analyses', { error: err.message });
    throw new DatabaseError();
  }
}

/**
 * Get a single analysis by ID, verifying ownership.
 */
async function getAnalysisById(analysisId, userId) {
  try {
    const analysisResult = await pool.query(
      `SELECT id, user_id, filename, sha256, file_size_bytes,
              status, analysis_version, overall_risk, risk_score,
              created_at, completed_at, error_code, error_message
       FROM analyses
       WHERE id = $1`,
      [analysisId]
    );

    if (analysisResult.rows.length === 0) return null;

    const analysis = analysisResult.rows[0];

    // Ownership check — return marker
    if (analysis.user_id !== userId) {
      return { forbidden: true };
    }

    return analysis;
  } catch (err) {
    logger.error('Database error fetching analysis', { error: err.message });
    throw new DatabaseError();
  }
}

/**
 * Get the full analysis with all related data (sessions, security_info, findings, risk, recommendations).
 */
async function getFullAnalysis(analysisId) {
  try {
    // Sessions + security_info
    const sessionsResult = await pool.query(
      `SELECT
         s.id AS session_id,
         s.session_ref,
         s.tcp_stream,
         s.protocol,
         s.service,
         s.service_port,
         s.src_ip,
         s.src_port,
         s.dst_ip,
         s.dst_port,
         s.encryption_mode,
         s.capture_completeness,
         s.risk_label,
         si.upgrade_advertised,
         si.upgrade_requested,
         si.upgrade_succeeded,
         si.authentication_before_tls,
         si.tls_version,
         si.cipher_suite,
         si.key_exchange,
         si.pfs,
         si.certificate_visibility,
         si.certificate_subject,
         si.certificate_issuer,
         si.certificate_valid_from,
         si.certificate_valid_to,
         si.certificate_key_algorithm,
         si.certificate_key_size,
         si.self_signed
       FROM sessions s
       LEFT JOIN security_info si ON si.session_id = s.id
       WHERE s.analysis_id = $1
       ORDER BY s.tcp_stream ASC NULLS LAST`,
      [analysisId]
    );

    // Findings
    const findingsResult = await pool.query(
      `SELECT f.id AS finding_id, s.session_ref AS session_id,
              f.finding_type, f.severity,
              f.title, f.description, f.confidence, f.evidence_json, f.created_at
       FROM findings f
       LEFT JOIN sessions s ON s.id = f.session_id
       WHERE f.analysis_id = $1
       ORDER BY f.created_at ASC`,
      [analysisId]
    );

    // Risk result
    const riskResult = await pool.query(
      `SELECT risk_label, risk_score, model_version, method, confidence
       FROM risk_results
       WHERE analysis_id = $1`,
      [analysisId]
    );

    // Recommendations
    const recsResult = await pool.query(
      `SELECT id AS recommendation_id, finding_id, priority, title, recommendation_text
       FROM recommendations
       WHERE analysis_id = $1
       ORDER BY priority ASC`,
      [analysisId]
    );

    // Build sessions with nested security/tls/certificate like the contract
    const sessions = sessionsResult.rows.map((row) => {
      const session = {
        session_id: row.session_ref || row.session_id,
        protocol: row.protocol,
        service: row.service,
        client_ip: row.src_ip,
        server_ip: row.dst_ip,
        client_port: row.src_port,
        server_port: row.dst_port || row.service_port,
        security: {
          encryption_mode: row.encryption_mode,
          upgrade_advertised: row.upgrade_advertised,
          upgrade_requested: row.upgrade_requested,
          upgrade_succeeded: row.upgrade_succeeded,
          authentication_before_tls: row.authentication_before_tls,
          capture_completeness: row.capture_completeness,
        },
        tls: null,
        certificate: null,
      };

      // Build TLS object if data exists
      if (row.tls_version) {
        session.tls = {
          version: row.tls_version,
          cipher_suite: row.cipher_suite,
          pfs: row.pfs,
        };
      }

      // Build certificate object
      if (row.certificate_subject || row.certificate_visibility) {
        if (row.certificate_visibility === 'NOT_OBSERVABLE') {
          session.certificate = { visibility: 'NOT_OBSERVABLE' };
        } else {
          session.certificate = {
            subject: row.certificate_subject,
            issuer: row.certificate_issuer,
            valid_from: row.certificate_valid_from,
            valid_until: row.certificate_valid_to,
            key_type: row.certificate_key_algorithm,
            key_size: row.certificate_key_size,
            self_signed: row.self_signed,
          };
        }
      }

      return session;
    });

    const findings = findingsResult.rows.map((row) => ({
      finding_id: row.finding_id,
      session_id: row.session_id,
      finding_type: row.finding_type,
      severity: row.severity,
      title: row.title,
      description: row.description,
      confidence: row.confidence,
      evidence: row.evidence_json,
    }));

    const risk = riskResult.rows[0]
      ? {
          score: parseFloat(riskResult.rows[0].risk_score),
          level: riskResult.rows[0].risk_label,
          model_version: riskResult.rows[0].model_version,
          method: riskResult.rows[0].method,
          confidence: riskResult.rows[0].confidence
            ? parseFloat(riskResult.rows[0].confidence)
            : null,
        }
      : null;

    const recommendations = recsResult.rows.map((row) => ({
      recommendation_id: row.recommendation_id,
      priority: row.priority,
      title: row.title,
      description: row.recommendation_text,
    }));

    return { sessions, findings, risk, recommendations };
  } catch (err) {
    logger.error('Database error fetching full analysis', { error: err.message });
    throw new DatabaseError();
  }
}

module.exports = {
  createUser,
  findUserByEmail,
  createAnalysis,
  updateAnalysisStatus,
  failAnalysis,
  persistAnalysisResult,
  getAnalysesByUser,
  getAnalysisById,
  getFullAnalysis,
};
