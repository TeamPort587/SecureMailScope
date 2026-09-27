const request = require('supertest');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const os = require('os');

jest.mock('../src/services/databaseService');
const db = require('../src/services/databaseService');

jest.mock('../src/services/sessionExportService');
const { exportSessionPcap } = require('../src/services/sessionExportService');

const env = require('../src/config/env');
const app = require('../src/server');

const TEST_USER = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'test@example.com',
};

const OTHER_USER = {
  id: '660e8400-e29b-41d4-a716-446655440001',
  email: 'other@example.com',
};

function getToken(user = TEST_USER) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

const MOCK_ANALYSIS = {
  id: 'a1b2c3d4-5678-90ab-cdef-1234567890ab',
  user_id: TEST_USER.id,
  filename: 'smtp_capture.pcap',
  sha256: '9f86d081884c7d659a2feaa0c55ad015',
  file_size_bytes: '1000',
  status: 'COMPLETED',
  analysis_version: 'mock-v1',
  overall_risk: 'HIGH',
  risk_score: '78.00',
  created_at: '2026-09-09T10:30:00Z',
  completed_at: '2026-09-09T10:30:07Z',
};

const MOCK_SESSION = {
  db_id: 'sess-uuid-001',
  analysis_id: MOCK_ANALYSIS.id,
  session_ref: 'smtp-001',
  tcp_stream: 0,
  protocol: 'SMTP',
  service: 'submission',
  service_port: 587,
  src_ip: '10.0.1.15',
  src_port: 49152,
  dst_ip: '203.0.113.25',
  dst_port: 587,
  encryption_mode: 'STARTTLS',
  capture_completeness: 'COMPLETE',
  risk_label: 'LOW',
};

describe('Session PCAP Export & Provenance Endpoints', () => {
  let tempCaptureFile;

  beforeAll(() => {
    // Create a temporary mock source capture file in configured test upload dir
    const uploadDir = path.resolve(env.UPLOAD_DIR);
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    tempCaptureFile = path.join(uploadDir, `${MOCK_ANALYSIS.id}.pcap`);
    fs.writeFileSync(tempCaptureFile, Buffer.from('mock pcap header and packets'));
  });

  afterAll(() => {
    if (fs.existsSync(tempCaptureFile)) {
      fs.unlinkSync(tempCaptureFile);
    }
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // IDOR & Authorization Tests
  // ===========================================================================

  describe('IDOR & Authorization Protection', () => {
    it('should reject unauthenticated request with 401', async () => {
      await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/pcap`)
        .expect(401);
    });

    it('should reject access to another user\'s session capture with 403 (IDOR check)', async () => {
      db.getAnalysisById.mockResolvedValue({ forbidden: true });

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/pcap`)
        .set('Authorization', `Bearer ${getToken(OTHER_USER)}`)
        .expect(403);

      expect(res.body.error.code).toBe('FORBIDDEN');
    });

    it('should return 404 if analysis does not exist', async () => {
      db.getAnalysisById.mockResolvedValue(null);

      const res = await request(app)
        .get('/api/analyses/non-existent-analysis/sessions/smtp-001/pcap')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(404);

      expect(res.body.error.code).toBe('ANALYSIS_NOT_FOUND');
    });

    it('should return 404 if session does not exist in analysis', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getSessionByRef.mockResolvedValue(null);

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/non-existent-session/pcap`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(404);

      expect(res.body.error.code).toBe('SESSION_NOT_FOUND');
    });

    it('should return 400 if session has no TCP stream', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getSessionByRef.mockResolvedValue({ ...MOCK_SESSION, tcp_stream: null });

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/pcap`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(400);

      expect(res.body.error.code).toBe('NO_TCP_STREAM');
    });
  });

  // ===========================================================================
  // Successful Download Tests
  // ===========================================================================

  describe('GET /api/analyses/:analysisId/sessions/:sessionId/pcap', () => {
    it('should stream extracted session PCAP with correct Wireshark headers', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getSessionByRef.mockResolvedValue(MOCK_SESSION);

      // Mock export implementation to write a valid temp file
      exportSessionPcap.mockImplementation(async (src, stream, target) => {
        fs.writeFileSync(target, Buffer.from('extracted-session-pcap-data'));
        return {
          tcp_stream: stream,
          packet_count: 24,
          file_size_bytes: 28,
          source_pcap_sha256: 'mock-source-sha',
          extracted_pcap_sha256: 'mock-extracted-sha',
          wireshark_filter: `tcp.stream == ${stream}`,
        };
      });

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/pcap`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.headers['content-type']).toBe('application/vnd.tcpdump.pcap');
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.headers['content-disposition']).toContain('stream_0.pcap');
      expect(res.headers['x-wireshark-filter']).toBe('tcp.stream == 0');
      expect(res.headers['x-packet-count']).toBe('24');
      expect(res.headers['x-source-sha256']).toBe('mock-source-sha');
      expect(res.headers['x-session-completeness']).toBe('COMPLETE');
      const responseData = res.text || (Buffer.isBuffer(res.body) ? res.body.toString() : '');
      expect(responseData).toBe('extracted-session-pcap-data');
    });
  });

  // ===========================================================================
  // Provenance Endpoint Tests
  // ===========================================================================

  describe('GET /api/analyses/:analysisId/sessions/:sessionId/provenance', () => {
    it('should return provenance metadata matching source capture', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getSessionByRef.mockResolvedValue(MOCK_SESSION);

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/provenance`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.body.analysis_id).toBe(MOCK_ANALYSIS.id);
      expect(res.body.session_id).toBe('smtp-001');
      expect(res.body.tcp_stream).toBe(0);
      expect(res.body.source_pcap_filename).toBe('smtp_capture.pcap');
      expect(res.body.source_pcap_sha256).toBe(MOCK_ANALYSIS.sha256);
      expect(res.body.wireshark_filter).toBe('tcp.stream == 0');
      expect(res.body.completeness).toBe('COMPLETE');
    });

    it('should deny access to provenance for unauthorized users', async () => {
      db.getAnalysisById.mockResolvedValue({ forbidden: true });

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/sessions/smtp-001/provenance`)
        .set('Authorization', `Bearer ${getToken(OTHER_USER)}`)
        .expect(403);

      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });
});
