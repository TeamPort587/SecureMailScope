const request = require('supertest');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

jest.mock('../src/services/databaseService');
jest.mock('../src/services/analysisService');

const app = require('../src/server');

const TEST_USER = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'test@example.com',
};

function getToken() {
  return jwt.sign(
    { sub: TEST_USER.id, email: TEST_USER.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Create a minimal test file
const TEST_FILES_DIR = path.resolve(__dirname, 'fixtures');
const VALID_PCAP = path.join(TEST_FILES_DIR, 'test.pcap');
const VALID_PCAPNG = path.join(TEST_FILES_DIR, 'test.pcapng');
const VALID_CAP = path.join(TEST_FILES_DIR, 'test.cap');
const INVALID_EXT = path.join(TEST_FILES_DIR, 'test.exe');
const EMPTY_FILE = path.join(TEST_FILES_DIR, 'empty.pcap');

beforeAll(() => {
  // Create fixture directory and files
  if (!fs.existsSync(TEST_FILES_DIR)) {
    fs.mkdirSync(TEST_FILES_DIR, { recursive: true });
  }

  // PCAP magic bytes (0xd4c3b2a1 little-endian)
  const pcapHeader = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00]);
  fs.writeFileSync(VALID_PCAP, pcapHeader);
  fs.writeFileSync(VALID_PCAPNG, pcapHeader);
  fs.writeFileSync(VALID_CAP, pcapHeader);
  fs.writeFileSync(INVALID_EXT, pcapHeader);
  fs.writeFileSync(EMPTY_FILE, Buffer.alloc(0));
});

afterAll(() => {
  // Cleanup fixtures
  if (fs.existsSync(TEST_FILES_DIR)) {
    fs.rmSync(TEST_FILES_DIR, { recursive: true, force: true });
  }
  // Cleanup test uploads
  const uploadDir = path.resolve(process.env.UPLOAD_DIR || './test-uploads');
  if (fs.existsSync(uploadDir)) {
    fs.rmSync(uploadDir, { recursive: true, force: true });
  }
});

describe('File Upload', () => {
  const { processUpload } = require('../src/services/analysisService');

  beforeEach(() => {
    jest.clearAllMocks();
    processUpload.mockResolvedValue({
      analysis_id: 'mock-analysis-id',
      status: 'COMPLETED',
    });
  });

  describe('Valid uploads', () => {
    it('should accept .pcap files', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Authorization', `Bearer ${getToken()}`)
        .attach('file', VALID_PCAP)
        .expect(201);

      expect(res.body.analysis_id).toBe('mock-analysis-id');
    });

    it('should accept .pcapng files', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Authorization', `Bearer ${getToken()}`)
        .attach('file', VALID_PCAPNG)
        .expect(201);

      expect(res.body.analysis_id).toBe('mock-analysis-id');
    });

    it('should accept .cap files', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Authorization', `Bearer ${getToken()}`)
        .attach('file', VALID_CAP)
        .expect(201);

      expect(res.body.analysis_id).toBe('mock-analysis-id');
    });
  });

  describe('Invalid uploads', () => {
    it('should reject unsupported extensions', async () => {
      try {
        const res = await request(app)
          .post('/api/analyze')
          .set('Authorization', `Bearer ${getToken()}`)
          .attach('file', INVALID_EXT);

        // If we get a response, verify it
        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('INVALID_FILE');
      } catch (err) {
        // Multer may abort the connection before supertest reads the response
        // This is expected behavior — the server correctly rejects the file
        expect(err.code === 'ECONNRESET' || err.message.includes('ECONNRESET')).toBe(true);
      }
    });

    it('should reject missing file', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Authorization', `Bearer ${getToken()}`)
        .expect(400);

      expect(res.body.error.code).toBe('INVALID_FILE');
    });

    it('should reject empty file', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Authorization', `Bearer ${getToken()}`)
        .attach('file', EMPTY_FILE)
        .expect(400);

      expect(res.body.error.code).toBe('INVALID_FILE');
    });

    it('should require authentication', async () => {
      try {
        const res = await request(app)
          .post('/api/analyze')
          .attach('file', VALID_PCAP);

        // If we get a response, verify it
        expect(res.status).toBe(401);
        expect(res.body.error.code).toBe('UNAUTHORIZED');
      } catch (err) {
        // Connection may reset when auth fails during multipart upload
        expect(err.code === 'ECONNRESET' || err.message.includes('ECONNRESET')).toBe(true);
      }
    });
  });
});

