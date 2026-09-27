const standardsService = require('../src/services/standardsService');
const { validateDjangoResponse } = require('../src/validators/analysisSchema');
const { getMockAnalysisResponse } = require('../src/services/mockDjango');

describe('Standards Context Service', () => {
  describe('TLS Version Evaluation (RFC 9325 / RFC 8996)', () => {
    it('evaluates TLS 1.2 as ACCEPTABLE with TLS 1.3 preferred without creating a vulnerability', () => {
      const session = {
        protocol: 'SMTP',
        tls: { version: 'TLS 1.2', cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', pfs: true },
        security: { encryption_mode: 'STARTTLS' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const tlsResult = results.find(r => r.field === 'tls_version');

      expect(tlsResult).toBeDefined();
      expect(tlsResult.status).toBe('ACCEPTABLE');
      expect(tlsResult.observed).toBe('TLS 1.2');
      expect(tlsResult.preferred).toEqual(['TLS 1.3']);
      expect(tlsResult.visualization).toBe('ordered_spectrum');
      expect(tlsResult.sources.some(s => s.name.includes('RFC 9325'))).toBe(true);
    });

    it('evaluates TLS 1.0 as DEPRECATED per RFC 8996', () => {
      const session = {
        protocol: 'POP3',
        tls: { version: 'TLS 1.0' },
        security: { encryption_mode: 'STARTTLS' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const tlsResult = results.find(r => r.field === 'tls_version');

      expect(tlsResult.status).toBe('DEPRECATED');
      expect(tlsResult.sources.some(s => s.name.includes('RFC 8996'))).toBe(true);
    });

    it('evaluates TLS 1.3 as PREFERRED', () => {
      const session = {
        protocol: 'IMAP',
        tls: { version: 'TLS 1.3' },
        security: { encryption_mode: 'IMPLICIT' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const tlsResult = results.find(r => r.field === 'tls_version');

      expect(tlsResult.status).toBe('PREFERRED');
    });
  });

  describe('Email Transport Security (RFC 8314)', () => {
    it('evaluates PLAINTEXT as NOT_RECOMMENDED', () => {
      const session = {
        protocol: 'SMTP',
        security: { encryption_mode: 'PLAINTEXT' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const encResult = results.find(r => r.field === 'email_encryption_mode');

      expect(encResult.status).toBe('DEPRECATED');
      expect(encResult.preferred).toContain('Implicit TLS (Dedicated Port)');
      expect(encResult.sources.some(s => s.name.includes('RFC 8314'))).toBe(true);
    });

    it('evaluates IMPLICIT as PREFERRED under RFC 8314 Section 3', () => {
      const session = {
        protocol: 'IMAP',
        security: { encryption_mode: 'IMPLICIT' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const encResult = results.find(r => r.field === 'email_encryption_mode');

      expect(encResult.status).toBe('PREFERRED');
    });

    it('evaluates STARTTLS as ACCEPTABLE under RFC 8314', () => {
      const session = {
        protocol: 'SMTP',
        security: { encryption_mode: 'STARTTLS' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const encResult = results.find(r => r.field === 'email_encryption_mode');

      expect(encResult.status).toBe('ACCEPTABLE');
    });
  });

  describe('Passive Epistemology & TLS 1.3 Unobservable Certificate', () => {
    it('marks certificate as NOT_OBSERVABLE when TLS 1.3 encrypts the handshake', () => {
      const session = {
        protocol: 'SMTP',
        tls: { version: 'TLS 1.3' },
        certificate: { visibility: 'NOT_OBSERVABLE' },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const certResult = results.find(r => r.field === 'certificate_validity');

      expect(certResult).toBeDefined();
      expect(certResult.status).toBe('NOT_OBSERVABLE');
      expect(certResult.visualization).toBe('status_assessment');
      expect(certResult.rationale).toContain('TLS 1.3');
    });

    it('evaluates RSA 2048 key size as ACCEPTABLE under NIST SP 800-52/57', () => {
      const session = {
        protocol: 'SMTP',
        tls: { version: 'TLS 1.2' },
        certificate: {
          key_type: 'RSA',
          key_size: 2048,
          valid_from: '2023-01-01T00:00:00Z',
          valid_until: '2027-01-01T00:00:00Z',
        },
      };
      const results = standardsService.evaluateSessionStandards(session);
      const keyResult = results.find(r => r.field === 'certificate_key_strength');

      expect(keyResult).toBeDefined();
      expect(keyResult.status).toBe('ACCEPTABLE');
      expect(keyResult.observed).toContain('2048-bit');
    });
  });

  describe('Schema Validation Compatibility', () => {
    it('validates mock response when standards_context is attached to sessions', () => {
      const mock = getMockAnalysisResponse({
        analysis_id: 'test-std',
        filename: 'test.pcap',
        sha256: 'abc123',
        size_bytes: 500,
      });

      // Attach standards_context to mock sessions
      for (const s of mock.sessions) {
        s.standards_context = standardsService.evaluateSessionStandards(s);
      }

      const val = validateDjangoResponse(mock);
      expect(val.success).toBe(true);
      expect(val.data.sessions[0].standards_context.length).toBeGreaterThan(0);
    });
  });
});
