const request = require('supertest');
const jwt = require('jsonwebtoken');

// Mock the database service
jest.mock('../src/services/databaseService');
const db = require('../src/services/databaseService');

const app = require('../src/server');

const TEST_USER = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'test@example.com',
  password_hash: '$2a$12$LJ3m4ys3Gy.lXIaYmGOLaO5T1xnBRfvMfU.XqG2a8PFfKSAJxJXy', // "TestPass123"
  created_at: '2026-09-09T10:00:00Z',
};

describe('Authentication', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // ===========================================================================
  // REGISTRATION
  // ===========================================================================

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      db.createUser.mockResolvedValue({
        id: TEST_USER.id,
        email: TEST_USER.email,
        created_at: TEST_USER.created_at,
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'test@example.com', password: 'TestPass123' })
        .expect(201);

      expect(res.body.status).toBe('success');
      expect(res.body.user.id).toBe(TEST_USER.id);
      expect(res.body.user.email).toBe(TEST_USER.email);
      expect(res.body.user).not.toHaveProperty('password');
      expect(res.body.user).not.toHaveProperty('password_hash');
    });

    it('should reject duplicate email', async () => {
      const error = new Error('duplicate');
      error.code = '23505';
      db.createUser.mockRejectedValue(error);

      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'test@example.com', password: 'TestPass123' })
        .expect(409);

      expect(res.body.status).toBe('error');
      expect(res.body.error.code).toBe('DUPLICATE_EMAIL');
    });

    it('should reject missing email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ password: 'TestPass123' })
        .expect(422);

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject missing password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'test@example.com' })
        .expect(422);

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject short password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'test@example.com', password: 'short' })
        .expect(422);

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should reject invalid email format', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'not-an-email', password: 'TestPass123' })
        .expect(422);

      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  // ===========================================================================
  // LOGIN
  // ===========================================================================

  describe('POST /api/auth/login', () => {
    it('should login successfully and return JWT', async () => {
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash('TestPass123', 12);

      db.findUserByEmail.mockResolvedValue({
        id: TEST_USER.id,
        email: TEST_USER.email,
        password_hash: hash,
      });

      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'TestPass123' })
        .expect(200);

      expect(res.body).toHaveProperty('token');
      expect(res.body.user.id).toBe(TEST_USER.id);
      expect(res.body.user.email).toBe(TEST_USER.email);
      expect(res.body.user).not.toHaveProperty('password_hash');

      // Verify JWT is valid
      const decoded = jwt.verify(res.body.token, process.env.JWT_SECRET);
      expect(decoded.sub).toBe(TEST_USER.id);
      expect(decoded.email).toBe(TEST_USER.email);
    });

    it('should reject non-existent user', async () => {
      db.findUserByEmail.mockResolvedValue(null);

      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'nobody@example.com', password: 'TestPass123' })
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject invalid password', async () => {
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash('CorrectPassword', 12);

      db.findUserByEmail.mockResolvedValue({
        id: TEST_USER.id,
        email: TEST_USER.email,
        password_hash: hash,
      });

      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'WrongPassword' })
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });
  });

  // ===========================================================================
  // JWT VALIDATION
  // ===========================================================================

  describe('JWT Authentication Middleware', () => {
    it('should reject request with no Authorization header', async () => {
      const res = await request(app)
        .get('/api/analyses')
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject request with invalid token', async () => {
      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject request with expired token', async () => {
      // Create a token that expired 10 seconds ago
      const now = Math.floor(Date.now() / 1000);
      const token = jwt.sign(
        { sub: TEST_USER.id, email: TEST_USER.email, iat: now - 20, exp: now - 10 },
        process.env.JWT_SECRET
      );

      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', `Bearer ${token}`)
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should reject malformed Authorization header', async () => {
      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', 'NotBearer some-token')
        .expect(401);

      expect(res.body.error.code).toBe('UNAUTHORIZED');
    });

    it('should accept valid JWT and pass user to handler', async () => {
      const token = jwt.sign(
        { sub: TEST_USER.id, email: TEST_USER.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      db.getAnalysesByUser.mockResolvedValue({
        items: [],
        pagination: { page: 1, limit: 20, total: 0 },
      });

      const res = await request(app)
        .get('/api/analyses')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(res.body).toHaveProperty('items');
    });
  });
});
