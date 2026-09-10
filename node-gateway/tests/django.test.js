const { validateDjangoResponse } = require('../src/validators/analysisSchema');
const { getMockAnalysisResponse } = require('../src/services/mockDjango');

describe('Django Response Validation', () => {
  const validMetadata = {
    analysis_id: 'test-id',
    filename: 'test.pcap',
    sha256: 'abc123',
    size_bytes: 1000,
  };

  describe('Valid responses', () => {
    it('should accept a valid mock Django response', () => {
      const mockResponse = getMockAnalysisResponse(validMetadata);
      const result = validateDjangoResponse(mockResponse);

      expect(result.success).toBe(true);
      expect(result.data.analysis_version).toBe('mock-v1');
      expect(result.data.sessions).toHaveLength(4);
      expect(result.data.findings).toHaveLength(5);
      expect(result.data.recommendations).toHaveLength(2);
    });

    it('should accept sessions with null TLS and certificate', () => {
      const response = getMockAnalysisResponse(validMetadata);
      // smtp-002 has null tls and certificate
      const result = validateDjangoResponse(response);
      expect(result.success).toBe(true);

      const smtpSession = result.data.sessions.find(
        (s) => s.session_id === 'smtp-002'
      );
      expect(smtpSession.tls).toBeNull();
      expect(smtpSession.certificate).toBeNull();
    });

    it('should accept certificate with visibility only', () => {
      const response = getMockAnalysisResponse(validMetadata);
      const result = validateDjangoResponse(response);
      expect(result.success).toBe(true);

      const pop3Session = result.data.sessions.find(
        (s) => s.session_id === 'pop3-001'
      );
      expect(pop3Session.certificate).toEqual({ visibility: 'NOT_OBSERVABLE' });
    });
  });

  describe('Invalid responses', () => {
    it('should reject missing analysis_version', () => {
      const response = getMockAnalysisResponse(validMetadata);
      delete response.analysis_version;

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
      expect(result.error).toContain('analysis_version');
    });

    it('should reject missing sessions', () => {
      const response = getMockAnalysisResponse(validMetadata);
      delete response.sessions;

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
    });

    it('should reject missing findings', () => {
      const response = getMockAnalysisResponse(validMetadata);
      delete response.findings;

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
    });

    it('should reject invalid risk_label on session', () => {
      const response = getMockAnalysisResponse(validMetadata);
      response.sessions[0].risk_label = 'INVALID_RISK';

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
    });

    it('should reject invalid protocol', () => {
      const response = getMockAnalysisResponse(validMetadata);
      response.sessions[0].protocol = 'FTP';

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
    });

    it('should reject invalid encryption mode', () => {
      const response = getMockAnalysisResponse(validMetadata);
      response.sessions[0].security.encryption_mode = 'INVALID';

      const result = validateDjangoResponse(response);
      expect(result.success).toBe(false);
    });

    it('should reject completely malformed data', () => {
      const result = validateDjangoResponse({ garbage: true });
      expect(result.success).toBe(false);
    });

    it('should reject null response', () => {
      const result = validateDjangoResponse(null);
      expect(result.success).toBe(false);
    });

    it('should reject string response', () => {
      const result = validateDjangoResponse('not json');
      expect(result.success).toBe(false);
    });
  });
});
