const request = require('supertest');
const jwt = require('jsonwebtoken');

// Mock dependencies
jest.mock('../src/services/databaseService');
jest.mock('../src/services/ollamaService');

const db = require('../src/services/databaseService');
const ollamaService = require('../src/services/ollamaService');
const promptService = require('../src/services/copilotPromptService');
const app = require('../src/server');

// ============================================================================
// TEST DATA
// ============================================================================

const TEST_USER = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'copilot-test@example.com',
};

const TEST_ANALYSIS = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  user_id: TEST_USER.id,
  filename: 'test-capture.pcap',
  status: 'COMPLETED',
  overall_risk: 'HIGH',
  risk_score: '0.82',
  created_at: '2026-09-10T10:00:00Z',
  completed_at: '2026-09-10T10:01:00Z',
};

const TEST_FULL_DATA = {
  sessions: [
    {
      session_id: 'sess-001',
      protocol: 'SMTP',
      service: 'smtp',
      client_ip: '192.168.1.10',
      server_ip: '10.0.0.5',
      client_port: 54321,
      server_port: 25,
      security: {
        encryption_mode: 'NONE',
        upgrade_advertised: true,
        upgrade_requested: false,
        upgrade_succeeded: false,
        authentication_before_tls: true,
        capture_completeness: 'FULL',
      },
      tls: null,
      certificate: null,
    },
  ],
  findings: [
    {
      finding_id: 'f-001',
      session_id: 'sess-001',
      finding_type: 'auth_before_tls',
      severity: 'CRITICAL',
      title: 'Authentication occurred before TLS',
      description: 'AUTH LOGIN was sent over plaintext before STARTTLS upgrade.',
      confidence: 0.98,
      evidence: { command: 'AUTH LOGIN', timestamp: '2026-09-10T10:00:15Z' },
    },
    {
      finding_id: 'f-002',
      session_id: 'sess-001',
      finding_type: 'deprecated_tls',
      severity: 'HIGH',
      title: 'Deprecated TLS 1.0 in use',
      description: 'Session negotiated TLS 1.0 which is deprecated per RFC 8996.',
      confidence: 0.95,
      evidence: { tls_version: 'TLS 1.0' },
    },
  ],
  risk: {
    level: 'HIGH',
    score: 0.82,
    model_version: 'rf-email-sec-v1',
    method: 'random_forest',
    confidence: 0.91,
  },
  recommendations: [
    {
      recommendation_id: 'r-001',
      priority: 'CRITICAL',
      title: 'Enforce STARTTLS before authentication',
      description: 'Configure smtpd_tls_auth_only = yes in Postfix main.cf.',
    },
  ],
};

/**
 * Create a valid JWT for testing.
 */
function createToken(user = TEST_USER) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// ============================================================================
// UNIT TESTS: copilotPromptService
// ============================================================================

describe('copilotPromptService', () => {
  describe('generateSuggestedQuestions', () => {
    it('should return exactly 4 suggestions', () => {
      const suggestions = promptService.generateSuggestedQuestions(
        TEST_FULL_DATA.findings,
        TEST_FULL_DATA.risk
      );

      expect(suggestions).toHaveLength(4);
    });

    it('should include auth_before_tls question when finding is present', () => {
      const suggestions = promptService.generateSuggestedQuestions(
        TEST_FULL_DATA.findings,
        TEST_FULL_DATA.risk
      );

      const hasAuthQuestion = suggestions.some((q) =>
        q.toLowerCase().includes('starttls before authentication')
      );
      expect(hasAuthQuestion).toBe(true);
    });

    it('should include deprecated TLS question when finding is present', () => {
      const suggestions = promptService.generateSuggestedQuestions(
        TEST_FULL_DATA.findings,
        TEST_FULL_DATA.risk
      );

      const hasTlsQuestion = suggestions.some((q) =>
        q.toLowerCase().includes('tls 1.0/1.1')
      );
      expect(hasTlsQuestion).toBe(true);
    });

    it('should always include executive summary question', () => {
      const suggestions = promptService.generateSuggestedQuestions(
        TEST_FULL_DATA.findings,
        TEST_FULL_DATA.risk
      );

      const hasExecSummary = suggestions.some((q) =>
        q.toLowerCase().includes('executive summary')
      );
      expect(hasExecSummary).toBe(true);
    });

    it('should return 4 suggestions even with no findings', () => {
      const suggestions = promptService.generateSuggestedQuestions([], null);

      expect(suggestions).toHaveLength(4);
      // Should include exec summary + 3 general questions
      const hasExecSummary = suggestions.some((q) =>
        q.toLowerCase().includes('executive summary')
      );
      expect(hasExecSummary).toBe(true);
    });

    it('should not duplicate questions', () => {
      const suggestions = promptService.generateSuggestedQuestions(
        TEST_FULL_DATA.findings,
        TEST_FULL_DATA.risk
      );

      const uniqueSet = new Set(suggestions);
      expect(uniqueSet.size).toBe(suggestions.length);
    });
  });

  describe('buildSystemPrompt', () => {
    it('should include analysis overview', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('ANALYSIS OVERVIEW');
      expect(prompt).toContain('test-capture.pcap');
    });

    it('should include risk level', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('HIGH');
    });

    it('should include session telemetry', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('SESSION TELEMETRY');
      expect(prompt).toContain('SMTP');
    });

    it('should include finding titles', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('SECURITY FINDINGS');
      expect(prompt).toContain('Authentication occurred before TLS');
      expect(prompt).toContain('Deprecated TLS 1.0 in use');
    });

    it('should include recommendations', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('RECOMMENDATIONS');
      expect(prompt).toContain('Enforce STARTTLS before authentication');
    });

    it('should flag authentication before TLS in session telemetry', () => {
      const prompt = promptService.buildSystemPrompt({
        analysis: TEST_ANALYSIS,
        ...TEST_FULL_DATA,
      });

      expect(prompt).toContain('authentication before TLS');
    });
  });
});

// ============================================================================
// INTEGRATION TESTS: /api/copilot endpoints
// ============================================================================

describe('Copilot API', () => {
  let token;

  beforeAll(() => {
    token = createToken();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // GET /api/copilot/status
  // -------------------------------------------------------------------------

  describe('GET /api/copilot/status', () => {
    it('should return online status when Ollama is available', async () => {
      ollamaService.checkStatus.mockResolvedValue({
        online: true,
        model: 'mailscope-sec:3b',
        available: true,
        models_loaded: ['mailscope-sec:3b'],
      });

      const res = await request(app)
        .get('/api/copilot/status')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(res.body.status).toBe('online');
      expect(res.body.model).toBe('mailscope-sec:3b');
      expect(res.body.model_available).toBe(true);
    });

    it('should return offline status when Ollama is down', async () => {
      ollamaService.checkStatus.mockResolvedValue({
        online: false,
        model: 'mailscope-sec:3b',
        available: false,
        models_loaded: [],
      });

      const res = await request(app)
        .get('/api/copilot/status')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(res.body.status).toBe('offline');
    });

    it('should reject unauthenticated requests', async () => {
      await request(app)
        .get('/api/copilot/status')
        .expect(401);
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/copilot/suggestions
  // -------------------------------------------------------------------------

  describe('POST /api/copilot/suggestions', () => {
    it('should return 4 suggestions for a valid analysis', async () => {
      db.getAnalysisById.mockResolvedValue(TEST_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(TEST_FULL_DATA);

      const res = await request(app)
        .post('/api/copilot/suggestions')
        .set('Authorization', `Bearer ${token}`)
        .send({ analysisId: TEST_ANALYSIS.id })
        .expect(200);

      expect(res.body.suggestions).toHaveLength(4);
      expect(Array.isArray(res.body.suggestions)).toBe(true);

      // Should all be non-empty strings
      res.body.suggestions.forEach((q) => {
        expect(typeof q).toBe('string');
        expect(q.length).toBeGreaterThan(10);
      });
    });

    it('should reject missing analysisId', async () => {
      const res = await request(app)
        .post('/api/copilot/suggestions')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(422);

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 404 for non-existent analysis', async () => {
      db.getAnalysisById.mockResolvedValue(null);

      await request(app)
        .post('/api/copilot/suggestions')
        .set('Authorization', `Bearer ${token}`)
        .send({ analysisId: 'nonexistent-id' })
        .expect(404);
    });

    it('should return 403 for analysis owned by another user', async () => {
      db.getAnalysisById.mockResolvedValue({ forbidden: true });

      await request(app)
        .post('/api/copilot/suggestions')
        .set('Authorization', `Bearer ${token}`)
        .send({ analysisId: TEST_ANALYSIS.id })
        .expect(403);
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/copilot/chat
  // -------------------------------------------------------------------------

  describe('POST /api/copilot/chat', () => {
    it('should return AI response for valid chat request', async () => {
      db.getAnalysisById.mockResolvedValue(TEST_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(TEST_FULL_DATA);

      ollamaService.checkStatus.mockResolvedValue({
        online: true,
        model: 'mailscope-sec:3b',
        available: true,
        models_loaded: ['mailscope-sec:3b'],
      });

      ollamaService.chat.mockResolvedValue({
        response: 'To enforce STARTTLS before auth in Postfix, add `smtpd_tls_auth_only = yes` to main.cf.',
        model: 'mailscope-sec:3b',
        totalDuration: 3500000000,
      });

      const res = await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: 'How do I fix STARTTLS?',
          analysisId: TEST_ANALYSIS.id,
        })
        .expect(200);

      expect(res.body.response).toContain('smtpd_tls_auth_only');
      expect(res.body.model).toBe('mailscope-sec:3b');
      expect(res.body.source).toBe('ollama');
    });

    it('should pass grounded system prompt to Ollama', async () => {
      db.getAnalysisById.mockResolvedValue(TEST_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(TEST_FULL_DATA);

      ollamaService.checkStatus.mockResolvedValue({
        online: true,
        model: 'mailscope-sec:3b',
        available: true,
        models_loaded: ['mailscope-sec:3b'],
      });

      ollamaService.chat.mockResolvedValue({
        response: 'Test response',
        model: 'mailscope-sec:3b',
        totalDuration: 1000000000,
      });

      await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: 'Explain the findings',
          analysisId: TEST_ANALYSIS.id,
        })
        .expect(200);

      // Verify the messages passed to ollamaService.chat
      expect(ollamaService.chat).toHaveBeenCalledTimes(1);
      const [messages] = ollamaService.chat.mock.calls[0];

      // First message should be the system prompt
      expect(messages[0].role).toBe('system');
      expect(messages[0].content).toContain('test-capture.pcap');
      expect(messages[0].content).toContain('Authentication occurred before TLS');

      // Last message should be the user's question
      const lastMsg = messages[messages.length - 1];
      expect(lastMsg.role).toBe('user');
      expect(lastMsg.content).toBe('Explain the findings');
    });

    it('should return 503 when Ollama is offline', async () => {
      db.getAnalysisById.mockResolvedValue(TEST_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(TEST_FULL_DATA);

      ollamaService.checkStatus.mockResolvedValue({
        online: false,
        model: 'mailscope-sec:3b',
        available: false,
        models_loaded: [],
      });

      const res = await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: 'How do I fix this?',
          analysisId: TEST_ANALYSIS.id,
        })
        .expect(503);

      expect(res.body.error.code).toBe('COPILOT_UNAVAILABLE');
    });

    it('should reject empty message', async () => {
      await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: '',
          analysisId: TEST_ANALYSIS.id,
        })
        .expect(422);
    });

    it('should reject missing analysisId', async () => {
      await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: 'Hello',
        })
        .expect(422);
    });

    it('should include conversation history in Ollama call', async () => {
      db.getAnalysisById.mockResolvedValue(TEST_ANALYSIS);
      db.getFullAnalysis.mockResolvedValue(TEST_FULL_DATA);

      ollamaService.checkStatus.mockResolvedValue({
        online: true,
        model: 'mailscope-sec:3b',
        available: true,
        models_loaded: ['mailscope-sec:3b'],
      });

      ollamaService.chat.mockResolvedValue({
        response: 'Follow-up response',
        model: 'mailscope-sec:3b',
        totalDuration: 2000000000,
      });

      await request(app)
        .post('/api/copilot/chat')
        .set('Authorization', `Bearer ${token}`)
        .send({
          message: 'Can you elaborate?',
          analysisId: TEST_ANALYSIS.id,
          history: [
            { role: 'user', content: 'What is wrong?' },
            { role: 'assistant', content: 'Auth before TLS is the main issue.' },
          ],
        })
        .expect(200);

      const [messages] = ollamaService.chat.mock.calls[0];

      // system + 2 history + 1 current = 4 messages
      expect(messages).toHaveLength(4);
      expect(messages[1].role).toBe('user');
      expect(messages[1].content).toBe('What is wrong?');
      expect(messages[2].role).toBe('assistant');
      expect(messages[3].role).toBe('user');
      expect(messages[3].content).toBe('Can you elaborate?');
    });
  });
});
