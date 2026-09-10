/**
 * Mock Django analysis response.
 *
 * Returns a deterministic valid analysis result matching the contract
 * defined in docs/contracts/django-analysis-response.json.
 *
 * Used when USE_MOCK_DJANGO=true for development and testing
 * without a running Django service.
 */

/**
 * Generate a mock analysis response.
 *
 * @param {object} metadata
 * @param {string} metadata.analysis_id
 * @param {string} metadata.filename
 * @param {string} metadata.sha256
 * @param {number} metadata.size_bytes
 * @returns {object}
 */
function getMockAnalysisResponse(metadata) {
  return {
    analysis_version: 'mock-v1',

    file: {
      analysis_id: metadata.analysis_id,
      filename: metadata.filename,
      sha256: metadata.sha256,
      size_bytes: metadata.size_bytes,
    },

    summary: {
      total_sessions: 4,
      smtp_sessions: 2,
      imap_sessions: 1,
      pop3_sessions: 1,
      plaintext_sessions: 1,
      starttls_sessions: 2,
      implicit_tls_sessions: 1,
      vulnerable_sessions: 2,
      findings_count: 5,
    },

    sessions: [
      {
        session_id: 'smtp-001',
        protocol: 'SMTP',
        service: 'submission',
        client_ip: '10.0.1.15',
        server_ip: '203.0.113.25',
        client_port: 49152,
        server_port: 587,
        security: {
          encryption_mode: 'STARTTLS',
          upgrade_advertised: 'YES',
          upgrade_requested: 'YES',
          upgrade_succeeded: 'YES',
          authentication_before_tls: 'NO',
          capture_completeness: 'COMPLETE',
        },
        tls: {
          version: 'TLS 1.2',
          cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          pfs: 'YES',
        },
        certificate: {
          subject: 'CN=mail.example.com',
          issuer: 'Example CA',
          valid_from: '2026-01-01T00:00:00Z',
          valid_until: '2027-01-01T00:00:00Z',
          key_type: 'RSA',
          key_size: 2048,
          self_signed: false,
        },
        risk_label: 'LOW',
      },
      {
        session_id: 'smtp-002',
        protocol: 'SMTP',
        service: 'submission',
        client_ip: '10.0.1.20',
        server_ip: '203.0.113.26',
        client_port: 49153,
        server_port: 587,
        security: {
          encryption_mode: 'STARTTLS',
          upgrade_advertised: 'YES',
          upgrade_requested: 'NO',
          upgrade_succeeded: 'NO',
          authentication_before_tls: 'YES',
          capture_completeness: 'COMPLETE',
        },
        tls: null,
        certificate: null,
        risk_label: 'CRITICAL',
      },
      {
        session_id: 'imap-001',
        protocol: 'IMAP',
        service: 'mail-access',
        client_ip: '10.0.1.30',
        server_ip: '203.0.113.30',
        client_port: 49154,
        server_port: 143,
        security: {
          encryption_mode: 'PLAINTEXT',
          upgrade_advertised: 'NO',
          upgrade_requested: 'NO',
          upgrade_succeeded: 'NO',
          authentication_before_tls: 'YES',
          capture_completeness: 'COMPLETE',
        },
        tls: null,
        certificate: null,
        risk_label: 'CRITICAL',
      },
      {
        session_id: 'pop3-001',
        protocol: 'POP3',
        service: 'mail-access',
        client_ip: '10.0.1.40',
        server_ip: '203.0.113.40',
        client_port: 49155,
        server_port: 995,
        security: {
          encryption_mode: 'IMPLICIT_TLS',
          upgrade_advertised: 'UNKNOWN',
          upgrade_requested: 'UNKNOWN',
          upgrade_succeeded: 'YES',
          authentication_before_tls: 'NO',
          capture_completeness: 'PARTIAL',
        },
        tls: {
          version: 'TLS 1.3',
          cipher_suite: 'TLS_AES_256_GCM_SHA384',
          pfs: 'YES',
        },
        certificate: {
          visibility: 'NOT_OBSERVABLE',
        },
        risk_label: 'LOW',
      },
    ],

    findings: [
      {
        finding_id: 'finding-001',
        session_id: 'smtp-002',
        finding_type: 'AUTH_BEFORE_TLS',
        severity: 'CRITICAL',
        title: 'Authentication occurred before TLS',
        description: 'Authentication-related traffic was observed before the STARTTLS upgrade.',
        confidence: 'OBSERVED',
        evidence: {
          protocol: 'SMTP',
          server_port: 587,
          authentication_before_tls: true,
        },
      },
      {
        finding_id: 'finding-002',
        session_id: 'smtp-002',
        finding_type: 'FAILED_STARTTLS',
        severity: 'HIGH',
        title: 'STARTTLS upgrade was not negotiated',
        description: 'STARTTLS was advertised by the server but not requested by the client.',
        confidence: 'OBSERVED',
        evidence: {
          upgrade_advertised: 'YES',
          upgrade_requested: 'NO',
          upgrade_succeeded: 'NO',
        },
      },
      {
        finding_id: 'finding-003',
        session_id: 'imap-001',
        finding_type: 'PLAINTEXT',
        severity: 'CRITICAL',
        title: 'Email traffic transmitted in plaintext',
        description: 'Plaintext IMAP session with authentication credentials observed.',
        confidence: 'OBSERVED',
        evidence: {
          protocol: 'IMAP',
          server_port: 143,
          upgrade_advertised: 'NO',
          upgrade_requested: 'NO',
          upgrade_succeeded: 'NO',
        },
      },
      {
        finding_id: 'finding-004',
        session_id: 'smtp-001',
        finding_type: 'PFS',
        severity: 'INFO',
        title: 'Forward secrecy was observed',
        description: 'The negotiated TLS 1.2 cipher suite provides forward secrecy.',
        confidence: 'OBSERVED',
        evidence: {
          tls_version: 'TLS 1.2',
          cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          pfs: 'YES',
        },
      },
      {
        finding_id: 'finding-005',
        session_id: 'pop3-001',
        finding_type: 'PFS',
        severity: 'INFO',
        title: 'Forward secrecy was observed',
        description: 'The TLS 1.3 session provides forward secrecy.',
        confidence: 'INFERRED',
        evidence: {
          tls_version: 'TLS 1.3',
          cipher_suite: 'TLS_AES_256_GCM_SHA384',
          pfs: 'YES',
        },
      },
    ],

    recommendations: [
      {
        recommendation_id: 'rec-001',
        priority: 'CRITICAL',
        title: 'Require TLS before authentication',
        description:
          'Configure SMTP submission clients and servers so authentication occurs only after a successful TLS upgrade.',
      },
      {
        recommendation_id: 'rec-002',
        priority: 'HIGH',
        title: 'Enable TLS protection for IMAP',
        description:
          'Use IMAPS or successfully negotiate STARTTLS before authentication.',
      },
    ],
  };
}

module.exports = { getMockAnalysisResponse };
