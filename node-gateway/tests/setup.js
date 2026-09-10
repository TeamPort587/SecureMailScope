/**
 * Jest test setup.
 *
 * Sets environment variables before any test modules load.
 * This runs before each test file.
 */

process.env.NODE_ENV = 'test';
process.env.PORT = '3001';
process.env.DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/securemailscope_test';
process.env.JWT_SECRET = 'test-jwt-secret-do-not-use-in-production';
process.env.JWT_EXPIRES_IN = '1h';
process.env.DJANGO_BASE_URL = 'http://localhost:8000';
process.env.DJANGO_INTERNAL_KEY = 'test-internal-key';
process.env.DJANGO_TIMEOUT_MS = '5000';
process.env.MAX_UPLOAD_SIZE_MB = '10';
process.env.UPLOAD_DIR = './test-uploads';
process.env.USE_MOCK_DJANGO = 'true';
process.env.RATE_LIMIT_WINDOW_MS = '900000';
process.env.RATE_LIMIT_MAX_REQUESTS = '1000';
process.env.OLLAMA_BASE_URL = 'http://localhost:11434';
process.env.OLLAMA_MODEL = 'mailscope-sec:3b';
process.env.OLLAMA_TIMEOUT_MS = '5000';

