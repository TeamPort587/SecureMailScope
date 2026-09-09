-- ==============================================================================
-- SecureMailScope Gateway — Database Schema
-- ==============================================================================
-- This migration creates all application tables for the Node.js API Gateway.
-- Run with: npm run migrate
-- ==============================================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==============================================================================
-- USERS
-- ==============================================================================
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- ANALYSES
-- ==============================================================================
CREATE TABLE IF NOT EXISTS analyses (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename            VARCHAR(512) NOT NULL,
    sha256              VARCHAR(64) NOT NULL,
    file_size_bytes     BIGINT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'QUEUED'
                        CHECK (status IN ('QUEUED', 'PROCESSING', 'COMPLETED', 'FAILED')),
    analysis_version    VARCHAR(50),
    overall_risk        VARCHAR(20),
    risk_score          NUMERIC(5, 2),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    error_code          VARCHAR(50),
    error_message       TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_user_id    ON analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_analyses_status     ON analyses(status);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC);

-- ==============================================================================
-- SESSIONS
-- ==============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id             UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    session_ref             VARCHAR(100),
    tcp_stream              INTEGER,
    protocol                VARCHAR(20) NOT NULL,
    service                 VARCHAR(50),
    service_port            INTEGER,
    src_ip                  VARCHAR(45),
    src_port                INTEGER,
    dst_ip                  VARCHAR(45),
    dst_port                INTEGER,
    encryption_mode         VARCHAR(30),
    capture_completeness    VARCHAR(20),
    risk_label              VARCHAR(20),
    start_time              TIMESTAMPTZ,
    end_time                TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_analysis_id ON sessions(analysis_id);

-- ==============================================================================
-- SECURITY_INFO  (1:1 with sessions)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS security_info (
    id                          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id                  UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,

    -- STARTTLS / upgrade fields
    upgrade_advertised          VARCHAR(10),
    upgrade_requested           VARCHAR(10),
    upgrade_succeeded           VARCHAR(10),
    authentication_before_tls   VARCHAR(10),

    -- TLS fields
    tls_version                 VARCHAR(20),
    cipher_suite                VARCHAR(100),
    key_exchange                VARCHAR(50),
    pfs                         VARCHAR(10),

    -- Certificate fields
    certificate_visibility      VARCHAR(30),
    certificate_subject         VARCHAR(512),
    certificate_issuer          VARCHAR(512),
    certificate_valid_from      TIMESTAMPTZ,
    certificate_valid_to        TIMESTAMPTZ,
    certificate_key_algorithm   VARCHAR(20),
    certificate_key_size        INTEGER,
    self_signed                 BOOLEAN
);

-- ==============================================================================
-- FINDINGS
-- ==============================================================================
CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    session_id      UUID REFERENCES sessions(id) ON DELETE SET NULL,
    finding_type    VARCHAR(50) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    title           VARCHAR(512) NOT NULL,
    description     TEXT,
    confidence      VARCHAR(20),
    evidence_json   JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis_id ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_id  ON findings(session_id);

-- ==============================================================================
-- RISK_RESULTS  (1:1 with analyses)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS risk_results (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL UNIQUE REFERENCES analyses(id) ON DELETE CASCADE,
    risk_label      VARCHAR(20) NOT NULL,
    risk_score      NUMERIC(5, 2),
    model_version   VARCHAR(50),
    method          VARCHAR(50),
    confidence      NUMERIC(4, 3),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- RECOMMENDATIONS
-- ==============================================================================
CREATE TABLE IF NOT EXISTS recommendations (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id             UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    finding_id              UUID REFERENCES findings(id) ON DELETE SET NULL,
    priority                VARCHAR(20) NOT NULL,
    title                   VARCHAR(512),
    recommendation_text     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_recommendations_analysis_id ON recommendations(analysis_id);
CREATE INDEX IF NOT EXISTS idx_recommendations_finding_id  ON recommendations(finding_id);
