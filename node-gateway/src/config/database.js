const { Pool } = require('pg');
const env = require('./env');
const logger = require('../utils/logger');

/**
 * PostgreSQL connection pool singleton.
 *
 * Uses DATABASE_URL from environment variables.
 * All queries should use pool.query() or pool.connect() for transactions.
 */
const pool = new Pool({
  connectionString: env.DATABASE_URL,
  // Reasonable pool defaults for MVP
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Log pool errors (connection failures, etc.)
pool.on('error', (err) => {
  logger.error('Unexpected PostgreSQL pool error', { error: err.message });
});

/**
 * Test database connectivity.
 * @returns {Promise<boolean>}
 */
async function testConnection() {
  try {
    const result = await pool.query('SELECT NOW()');
    logger.info('PostgreSQL connected', { time: result.rows[0].now });
    return true;
  } catch (err) {
    logger.error('PostgreSQL connection failed', { error: err.message });
    return false;
  }
}

module.exports = { pool, testConnection };
