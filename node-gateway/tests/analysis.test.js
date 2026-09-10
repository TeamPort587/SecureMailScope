const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/services/databaseService');
const db = require('../src/services/databaseService');

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
  filename: 'test.pcap',
  sha256: '9f86d081884c7d659a2feaa0c55ad015',
  file_size_bytes: '1000',
  status: 'COMPLETED',
  analysis_version: 'mock-v1',
  overall_risk: 'HIGH',
  risk_score: '78.00',
  created_at: '2026-09-09T10:30:00Z',
  completed_at: '2026-09-09T10:30:07Z',
  error_code: null,
  error_message: null,
};

const MOCK_FULL_DATA = {
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
  ],
  findings: [
    {
      finding_id: 'finding-001',
      session_id: 'session-db-id',
      finding_type: 'AUTH_BEFORE_TLS',
      severity: 'CRITICAL',
      title: 'Authentication occurred before TLS',
      description: 'Auth traffic observed before STARTTLS.',
      confidence: 'OBSERVED',
      evidence: { protocol: 'SMTP' },
    },
  ],
  recommendations: [
    {
      recommendation_id: 'rec-001',
      priority: 'CRITICAL',
      title: 'Require TLS before auth',
      description: 'Configure TLS upgrade before auth.',
    },
  ],
};

describe('Analysis API', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // GET /api/health
  // ===========================================================================

  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const res = await request(app)
        .get('/api/health')
        .expect(200);

      expect(res.body).toEqual({
        status: 'ok',
        service: 'gateway',
        version: '1.0.0',
      });
    });
  });

  // ===========================================================================
  // GET /api/analyses
  // ===========================================================================

  describe('GET /api/analyses', () => {
    it('should return paginated analyses for authenticated user', async () => {
      db.getAnalysesByUser.mockResolvedValue({
        items: [
          {
            analysis_id: MOCK_ANALYSIS.id,
            filename: 'test.pcap',
            status: 'COMPLETED',
            risk_label: 'HIGH',
            risk_score: 78,
            session_count: 4,
            finding_count: 5,
            created_at: MOCK_ANALYSIS.created_at,
            completed_at: MOCK_ANALYSIS.completed_at,
            error_code: null,
            error_message: null,
          },
        ],
        pagination: { page: 1, limit: 20, total: 1 },
      });

      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.body.items).toHaveLength(1);
      expect(res.body.items[0].analysis_id).toBe(MOCK_ANALYSIS.id);
      expect(res.body.pagination.total).toBe(1);
    });

    it('should support pagination parameters', async () => {
      db.getAnalysesByUser.mockResolvedValue({
        items: [],
        pagination: { page: 2, limit: 5, total: 0 },
      });

      await request(app)
        .get('/api/analyses?page=2&limit=5')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(db.getAnalysesByUser).toHaveBeenCalledWith(
        TEST_USER.id,
        { page: 2, limit: 5 }
      );
    });

    it('should return empty list for user with no analyses', async () => {
      db.getAnalysesByUser.mockResolvedValue({
        items: [],
        pagination: { page: 1, limit: 20, total: 0 },
      });

      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.body.items).toHaveLength(0);
      expect(res.body.pagination.total).toBe(0);
    });

    it('should require authentication', async () => {
      await request(app)
        .get('/api/analyses')
        .expect(401);
    });
  });

  // ===========================================================================
  // GET /api/analyses/:analysisId
  // ===========================================================================

  describe('GET /api/analyses/:analysisId', () => {
    it('should return full analysis for owner', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(MOCK_FULL_DATA);

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.body.analysis_id).toBe(MOCK_ANALYSIS.id);
      expect(res.body.status).toBe('COMPLETED');
      expect(res.body.sessions).toHaveLength(1);
      expect(res.body.sessions[0].risk_label).toBe('LOW');
      expect(res.body.findings).toHaveLength(1);
      expect(res.body.risk).toBeUndefined();
      expect(res.body.recommendations).toHaveLength(1);
    });

    it('should return 404 for non-existent analysis', async () => {
      db.getAnalysisById.mockResolvedValue(null);

      const res = await request(app)
        .get('/api/analyses/non-existent-id')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(404);

      expect(res.body.error.code).toBe('ANALYSIS_NOT_FOUND');
    });

    it('should return 403 for another user\'s analysis', async () => {
      db.getAnalysisById.mockResolvedValue({ forbidden: true });

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}`)
        .set('Authorization', `Bearer ${getToken(OTHER_USER)}`)
        .expect(403);

      expect(res.body.error.code).toBe('FORBIDDEN');
    });
  });

  // ===========================================================================
  // GET /api/analyses/:analysisId/export
  // ===========================================================================

  describe('GET /api/analyses/:analysisId/export', () => {
    it('should export complete analysis as JSON', async () => {
      db.getAnalysisById.mockResolvedValue(MOCK_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(MOCK_FULL_DATA);

      const res = await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/export`)
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(200);

      expect(res.body.export_version).toBe('1.0.0');
      expect(res.body.exported_at).toBeDefined();
      expect(res.body.analysis.analysis_id).toBe(MOCK_ANALYSIS.id);
      expect(res.body.sessions).toHaveLength(1);
      expect(res.body.findings).toHaveLength(1);
      expect(res.headers['content-disposition']).toContain('attachment');
    });

    it('should return 404 for non-existent analysis', async () => {
      db.getAnalysisById.mockResolvedValue(null);

      await request(app)
        .get('/api/analyses/non-existent-id/export')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(404);
    });

    it('should return 403 for another user\'s analysis', async () => {
      db.getAnalysisById.mockResolvedValue({ forbidden: true });

      await request(app)
        .get(`/api/analyses/${MOCK_ANALYSIS.id}/export`)
        .set('Authorization', `Bearer ${getToken(OTHER_USER)}`)
        .expect(403);
    });
  });

  // ===========================================================================
  // 404 catch-all
  // ===========================================================================

  describe('404 catch-all', () => {
    it('should return 404 for unknown endpoints', async () => {
      const res = await request(app)
        .get('/api/nonexistent')
        .expect(404);

      expect(res.body.error.code).toBe('NOT_FOUND');
    });
  });
});
