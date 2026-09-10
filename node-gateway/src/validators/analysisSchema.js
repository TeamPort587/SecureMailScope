const { z } = require('zod');

/**
 * Strict Zod schema for validating Django analysis responses.
 *
 * Matches the contract defined in docs/contracts/django-analysis-response.json.
 * Validates structure before any data is persisted to PostgreSQL.
 *
 * On validation failure: INVALID_ANALYSIS_RESPONSE
 */

// -- Enums / value sets --------------------------------------------------------

const yesNoUnknown = z.enum(['YES', 'NO', 'UNKNOWN']);
const protocol = z.enum(['SMTP', 'IMAP', 'POP3', 'UNKNOWN']);
const severity = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const confidence = z.enum(['OBSERVED', 'INFERRED', 'SUSPECTED']);
const encryptionMode = z.enum(['PLAINTEXT', 'STARTTLS', 'IMPLICIT_TLS', 'UNKNOWN']);
const captureCompleteness = z.enum(['COMPLETE', 'PARTIAL', 'UNKNOWN']);
const priority = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const riskLevel = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']);

// -- Certificate schema (can be full object, visibility-only, or null) ----------

const fullCertificateSchema = z.object({
  subject: z.string(),
  issuer: z.string(),
  valid_from: z.string(),
  valid_until: z.string(),
  key_type: z.string(),
  key_size: z.number().int().positive(),
  self_signed: z.boolean(),
});

const visibilityCertificateSchema = z.object({
  visibility: z.string(),
});

const certificateSchema = z
  .union([fullCertificateSchema, visibilityCertificateSchema])
  .nullable();

// -- TLS schema ----------------------------------------------------------------

const tlsSchema = z
  .object({
    version: z.string().nullable().optional(),
    cipher_suite: z.string().nullable().optional(),
    pfs: yesNoUnknown.optional(),
  })
  .nullable();

// -- Security schema -----------------------------------------------------------

const securitySchema = z.object({
  encryption_mode: encryptionMode,
  upgrade_advertised: yesNoUnknown,
  upgrade_requested: yesNoUnknown,
  upgrade_succeeded: yesNoUnknown,
  authentication_before_tls: yesNoUnknown,
  capture_completeness: captureCompleteness,
});

// -- Session schema ------------------------------------------------------------

const sessionSchema = z.object({
  session_id: z.string(),
  protocol: protocol,
  service: z.string().optional(),
  client_ip: z.string(),
  server_ip: z.string(),
  client_port: z.number().int(),
  server_port: z.number().int(),
  security: securitySchema,
  tls: tlsSchema,
  certificate: certificateSchema,
  risk_label: riskLevel.optional(),
});

// -- Finding schema ------------------------------------------------------------

const findingSchema = z.object({
  finding_id: z.string(),
  session_id: z.string(),
  finding_type: z.string(),
  severity: severity,
  title: z.string(),
  description: z.string(),
  confidence: confidence,
  evidence: z.record(z.unknown()), // JSONB-compatible
});

// -- Risk schema ---------------------------------------------------------------

const riskSchema = z.object({
  score: z.number().min(0).max(100),
  level: riskLevel,
  model_version: z.string(),
  method: z.string().optional(),
  confidence: z.number().min(0).max(1).optional(),
});

// -- Recommendation schema -----------------------------------------------------

const recommendationSchema = z.object({
  recommendation_id: z.string(),
  priority: priority,
  title: z.string(),
  description: z.string(),
});

// -- Summary schema ------------------------------------------------------------

const summarySchema = z.object({
  total_sessions: z.number().int().min(0),
  smtp_sessions: z.number().int().min(0).optional(),
  imap_sessions: z.number().int().min(0).optional(),
  pop3_sessions: z.number().int().min(0).optional(),
  plaintext_sessions: z.number().int().min(0).optional(),
  starttls_sessions: z.number().int().min(0).optional(),
  implicit_tls_sessions: z.number().int().min(0).optional(),
  vulnerable_sessions: z.number().int().min(0).optional(),
  findings_count: z.number().int().min(0),
});

// -- File echo schema (optional — Django may echo back file metadata) ----------

const fileSchema = z.object({
  analysis_id: z.string(),
  filename: z.string(),
  sha256: z.string(),
  size_bytes: z.number().int().positive(),
}).optional();

// ==============================================================================
// TOP-LEVEL ANALYSIS RESPONSE SCHEMA
// ==============================================================================

const djangoAnalysisResponseSchema = z.object({
  analysis_version: z.string(),
  file: fileSchema,
  summary: summarySchema,
  sessions: z.array(sessionSchema),
  findings: z.array(findingSchema),
  recommendations: z.array(recommendationSchema),
});

/**
 * Validate a Django analysis response.
 *
 * @param {object} data - Raw response from Django
 * @returns {{ success: true, data: object } | { success: false, error: string }}
 */
function validateDjangoResponse(data) {
  const result = djangoAnalysisResponseSchema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  const errorMessages = result.error.issues
    .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
    .join('; ');

  return {
    success: false,
    error: `Django response validation failed: ${errorMessages}`,
  };
}

module.exports = {
  djangoAnalysisResponseSchema,
  validateDjangoResponse,
};
