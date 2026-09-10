import { describe, it, expect } from 'vitest';
import mockAnalysis from '../mock/mockAnalysis.json';
import { DEMO_PRESETS } from '../mock/demoCaptures';

describe('Shared Contract Compliance (node-react-analysis-response.json)', () => {
  function validateAnalysisContract(data) {
    // 1. Root fields
    expect(data).toHaveProperty('analysis_id');
    expect(typeof data.analysis_id).toBe('string');
    expect(data).toHaveProperty('status');
    expect(data).toHaveProperty('filename');
    expect(data).toHaveProperty('uploaded_at');

    // 2. Summary
    expect(data).toHaveProperty('summary');
    expect(typeof data.summary.total_sessions).toBe('number');
    expect(typeof data.summary.vulnerable_sessions).toBe('number');
    expect(typeof data.summary.findings_count).toBe('number');

    // 3. Risk - PCAP files do not have a collective risk label
    expect(data.risk).toBeUndefined();

    // 4. Sessions array
    expect(Array.isArray(data.sessions)).toBe(true);
    data.sessions.forEach((s) => {
      expect(s).toHaveProperty('session_id');
      expect(s).toHaveProperty('protocol');
      expect(s).toHaveProperty('risk_label');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(s.risk_label);
      expect(s).toHaveProperty('security');
      expect(s.security).toHaveProperty('encryption_mode');
      expect(s.security).toHaveProperty('upgrade_advertised');
      expect(s.security).toHaveProperty('upgrade_requested');
      expect(s.security).toHaveProperty('upgrade_succeeded');
      expect(s.security).toHaveProperty('authentication_before_tls');

      // Nullable sections
      if (s.tls !== null) {
        expect(s.tls).toHaveProperty('version');
        expect(s.tls).toHaveProperty('cipher_suite');
        expect(s.tls).toHaveProperty('pfs');
      }

      if (s.certificate !== null && s.certificate.visibility !== 'NOT_OBSERVABLE') {
        expect(s.certificate).toHaveProperty('subject');
        expect(s.certificate).toHaveProperty('issuer');
      }
    });

    // 5. Findings array
    expect(Array.isArray(data.findings)).toBe(true);
    data.findings.forEach((f) => {
      expect(f).toHaveProperty('finding_id');
      expect(f).toHaveProperty('session_id');
      expect(f).toHaveProperty('finding_type');
      expect(f).toHaveProperty('severity');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(f.severity);
      expect(f).toHaveProperty('title');
      expect(f).toHaveProperty('description');
    });

    // 6. Recommendations array
    expect(Array.isArray(data.recommendations)).toBe(true);
    data.recommendations.forEach((r) => {
      expect(r).toHaveProperty('recommendation_id');
      expect(r).toHaveProperty('priority');
      expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).toContain(r.priority);
      expect(r).toHaveProperty('title');
      expect(r).toHaveProperty('description');
    });
  }

  it('verifies mockAnalysis.json strictly follows the contract', () => {
    validateAnalysisContract(mockAnalysis);
  });

  it('verifies all demo capture presets follow the contract', () => {
    DEMO_PRESETS.forEach((preset) => {
      validateAnalysisContract(preset.data);
    });
  });
});
