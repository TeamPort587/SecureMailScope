import { describe, it, expect, vi } from 'vitest';
import { generatePdfReport } from '../utils/pdfReportGenerator';
import baseMock from '../mock/mockAnalysis.json';
import { DEMO_PRESETS } from '../mock/demoCaptures';

describe('PDF Report Generator Tests', () => {
  it('throws an error if no analysis object is passed', async () => {
    await expect(generatePdfReport(null)).rejects.toThrow(/Cannot generate PDF/i);
  });

  it('generates a valid PDF report for baseMock without error', async () => {
    // Generate without initiating browser download in test environment
    const result = await generatePdfReport(baseMock, { download: false });

    expect(result).toBeDefined();
    expect(result.doc).toBeDefined();
    expect(result.blob).toBeInstanceOf(Blob);
    expect(result.blob.size).toBeGreaterThan(1000);
    expect(result.filename).toContain('SecureMailScope_Analysis_Report_');
    expect(result.filename).toContain('smtp_capture.pcap.pdf');

    // Document has multiple pages (due to detailed findings, sessions, and tables)
    expect(result.doc.internal.getNumberOfPages()).toBeGreaterThanOrEqual(1);
  });

  it('generates a valid PDF report for demo-secure preset with clean TLS 1.3 traffic', async () => {
    const secureDemo = DEMO_PRESETS.find((d) => d.id === 'demo-secure');
    expect(secureDemo).toBeDefined();

    const result = await generatePdfReport(secureDemo.data, { download: false });
    expect(result).toBeDefined();
    expect(result.blob.size).toBeGreaterThan(1000);
    expect(result.filename).toContain('secure_mail_gateway_traffic.pcap.pdf');
  });

  it('generates a valid PDF report for empty/minimal analysis data', async () => {
    const minimalAnalysis = {
      analysis_id: 'min-12345',
      filename: 'empty_test.pcap',
      file_size_bytes: 512,
      sessions: [],
      findings: [],
      risk: {
        level: 'LOW',
        score: 0,
      },
    };

    const result = await generatePdfReport(minimalAnalysis, { download: false });
    expect(result).toBeDefined();
    expect(result.blob.size).toBeGreaterThan(500);
    expect(result.doc.internal.getNumberOfPages()).toBeGreaterThanOrEqual(1);
  });
});
