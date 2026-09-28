-- =============================================================================
-- SecureMailScope — Initial Schema Migration
-- Run once against your PostgreSQL database:
--   psql -U postgres -d securemailscope -f migrate.sql
-- =============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- USERS
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- ANALYSES
-- =============================================================================

CREATE TABLE IF NOT EXISTS analyses (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename          TEXT NOT NULL,
  sha256            TEXT,
  file_size_bytes   BIGINT,
  status            TEXT NOT NULL DEFAULT 'PROCESSING',
  analysis_version  TEXT,
  overall_risk      TEXT,
  risk_score        NUMERIC(7,4),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  completed_at      TIMESTAMPTZ,
  error_code        TEXT,
  error_message     TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_user_id ON analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_analyses_status  ON analyses(status);

-- =============================================================================
-- SESSIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS sessions (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id           UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  session_ref           TEXT,
  tcp_stream            INTEGER,
  protocol              TEXT,
  service               TEXT,
  service_port          INTEGER,
  src_ip                TEXT,
  src_port              INTEGER,
  dst_ip                TEXT,
  dst_port              INTEGER,
  encryption_mode       TEXT,
  capture_completeness  TEXT,
  risk_label            TEXT,
  start_time            TIMESTAMPTZ,
  end_time              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_analysis_id ON sessions(analysis_id);

-- =============================================================================
-- SECURITY INFO (1:1 with sessions)
-- All fields TEXT to handle UNKNOWN/null values from analysis engine
-- =============================================================================

CREATE TABLE IF NOT EXISTS security_info (
  id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id                UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
  upgrade_advertised        TEXT,
  upgrade_requested         TEXT,
  upgrade_succeeded         TEXT,
  authentication_before_tls TEXT,
  tls_version               TEXT,
  cipher_suite              TEXT,
  key_exchange              TEXT,
  pfs                       TEXT,
  certificate_visibility    TEXT,
  certificate_subject       TEXT,
  certificate_issuer        TEXT,
  certificate_valid_from    TIMESTAMPTZ,
  certificate_valid_to      TIMESTAMPTZ,
  certificate_key_algorithm TEXT,
  certificate_key_size      INTEGER,
  self_signed               TEXT
);

-- =============================================================================
-- FINDINGS
-- =============================================================================

CREATE TABLE IF NOT EXISTS findings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id   UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  session_id    UUID REFERENCES sessions(id) ON DELETE SET NULL,
  finding_type  TEXT NOT NULL,
  severity      TEXT NOT NULL,
  title         TEXT,
  description   TEXT,
  confidence    TEXT,
  evidence_json JSONB,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_id  ON findings(session_id);

-- =============================================================================
-- RISK RESULTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS risk_results (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id    UUID NOT NULL UNIQUE REFERENCES analyses(id) ON DELETE CASCADE,
  risk_label     TEXT,
  risk_score     NUMERIC(7,4),
  model_version  TEXT,
  method         TEXT,
  confidence     NUMERIC(7,4)
);

-- =============================================================================
-- RECOMMENDATIONS
-- =============================================================================

CREATE TABLE IF NOT EXISTS recommendations (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id         UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  finding_id          UUID REFERENCES findings(id) ON DELETE SET NULL,
  priority            TEXT,
  title               TEXT,
  recommendation_text TEXT,
  affected_sessions   JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_recommendations_analysis_id ON recommendations(analysis_id);

-- =============================================================================
-- ANOMALY RESULTS (Isolation Forest)
-- =============================================================================

CREATE TABLE IF NOT EXISTS anomaly_results (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id           UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  session_id            UUID REFERENCES sessions(id) ON DELETE CASCADE,
  status                TEXT NOT NULL,
  classification        TEXT,
  is_anomalous          BOOLEAN,
  raw_score             NUMERIC(7,4),
  decision_score        NUMERIC(7,4),
  threshold             NUMERIC(7,4),
  model_version         TEXT,
  feature_schema_version TEXT,
  warnings_json         JSONB,
  explanation_json      JSONB,
  created_at            TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomaly_results_analysis_id ON anomaly_results(analysis_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_session_id  ON anomaly_results(session_id);

-- =============================================================================
-- DONE
-- =============================================================================

\echo 'Migration complete.'