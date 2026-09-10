const { transformForPersistence } = require('../src/services/analysisService');
const { getMockAnalysisResponse } = require('../src/services/mockDjango');

/**
 * Database tests — these test the data transformation layer and
 * the database service logic without requiring a live PostgreSQL instance.
 *
 * For full integration tests with PostgreSQL, see analysis.test.js.
 */

describe('Database Service — Data Transformation', () => {
  const validMetadata = {
    analysis_id: 'test-id',
    filename: 'test.pcap',
    sha256: 'abc123',
    size_bytes: 1000,
  };

  describe('transformForPersistence', () => {
    it('should map contract session fields to DB format', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      expect(mapped.sessions).toHaveLength(4);

      const smtp = mapped.sessions[0];
      expect(smtp.session_ref).toBe('smtp-001');
      expect(smtp.protocol).toBe('SMTP');
      expect(smtp.src_ip).toBe('10.0.1.15');       // was client_ip
      expect(smtp.dst_ip).toBe('203.0.113.25');     // was server_ip
      expect(smtp.src_port).toBe(49152);            // was client_port
      expect(smtp.dst_port).toBe(587);              // was server_port
      expect(smtp.service).toBe('submission');
      expect(smtp.encryption_mode).toBe('STARTTLS');
    });

    it('should flatten security/tls/certificate into security_info', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      const smtp = mapped.sessions[0];
      const si = smtp.security_info;

      // Security fields
      expect(si.upgrade_advertised).toBe('YES');
      expect(si.upgrade_requested).toBe('YES');
      expect(si.upgrade_succeeded).toBe('YES');
      expect(si.authentication_before_tls).toBe('NO');

      // TLS fields
      expect(si.tls_version).toBe('TLS 1.2');
      expect(si.cipher_suite).toBe('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384');
      expect(si.pfs).toBe('YES');

      // Certificate fields
      expect(si.certificate_subject).toBe('CN=mail.example.com');
      expect(si.certificate_issuer).toBe('Example CA');
      expect(si.certificate_key_algorithm).toBe('RSA');
      expect(si.certificate_key_size).toBe(2048);
      expect(si.self_signed).toBe(false);
    });

    it('should handle null TLS and certificate', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      // smtp-002 has null tls and certificate
      const smtp2 = mapped.sessions[1];
      expect(smtp2.security_info.tls_version).toBeNull();
      expect(smtp2.security_info.cipher_suite).toBeNull();
      expect(smtp2.security_info.certificate_subject).toBeNull();
    });

    it('should handle visibility-only certificate', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      // pop3-001 has certificate with only visibility
      const pop3 = mapped.sessions[3];
      expect(pop3.security_info.certificate_visibility).toBe('NOT_OBSERVABLE');
      expect(pop3.security_info.certificate_subject).toBeNull();
    });

    it('should map session risk_label to DB format', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      expect(mapped.sessions[0].risk_label).toBe('LOW');
      expect(mapped.sessions[1].risk_label).toBe('CRITICAL');
      expect(mapped.sessions[2].risk_label).toBe('CRITICAL');
      expect(mapped.sessions[3].risk_label).toBe('LOW');
      expect(mapped.risk).toBeNull();
    });

    it('should map finding evidence to evidence_json', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      expect(mapped.findings).toHaveLength(5);

      const finding = mapped.findings[0];
      expect(finding.finding_ref).toBe('finding-001');
      expect(finding.session_ref).toBe('smtp-002');
      expect(finding.finding_type).toBe('AUTH_BEFORE_TLS');
      expect(finding.severity).toBe('CRITICAL');
      expect(finding.evidence_json).toEqual({
        protocol: 'SMTP',
        server_port: 587,
        authentication_before_tls: true,
      });
    });

    it('should map recommendation description to recommendation_text', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      expect(mapped.recommendations).toHaveLength(2);

      const rec = mapped.recommendations[0];
      expect(rec.priority).toBe('CRITICAL');
      expect(rec.title).toBe('Require TLS before authentication');
      expect(rec.recommendation_text).toContain('authentication occurs only after');
    });

    it('should set analysis_version from response', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const mapped = transformForPersistence(response);

      expect(mapped.analysis_version).toBe('mock-v1');
    });
  });
});
