const dotenv = require('dotenv');
const path = require('path');
const { z } = require('zod');

// Load .env from node-gateway root
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),
  JWT_EXPIRES_IN: z.string().default('24h'),

  DJANGO_BASE_URL: z.string().url().default('http://localhost:8000'),
  DJANGO_INTERNAL_KEY: z.string().min(1, 'DJANGO_INTERNAL_KEY is required'),
  DJANGO_TIMEOUT_MS: z.coerce.number().int().positive().default(120000),

  MAX_UPLOAD_SIZE_MB: z.coerce.number().int().positive().default(100),
  UPLOAD_DIR: z.string().default('./uploads'),

  USE_MOCK_DJANGO: z
    .string()
    .transform((val) => val === 'true')
    .default('false'),

  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(900000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(100),
});

let env;

try {
  env = envSchema.parse(process.env);
} catch (error) {
  console.error('❌ Invalid environment configuration:');
  if (error instanceof z.ZodError) {
    error.issues.forEach((issue) => {
      console.error(`   ${issue.path.join('.')}: ${issue.message}`);
    });
  }
  process.exit(1);
}

module.exports = env;
