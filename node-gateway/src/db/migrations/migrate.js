/**
 * Simple migration runner.
 *
 * Reads SQL files from src/db/schema/ and executes them in order.
 * Usage: npm run migrate
 */

const fs = require('fs');
const path = require('path');

// Load env manually since this script runs standalone
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env') });

const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set. Check your .env file.');
  process.exit(1);
}

async function migrate() {
  const pool = new Pool({ connectionString: DATABASE_URL });

  try {
    console.log('🔄 Connecting to PostgreSQL...');
    await pool.query('SELECT NOW()');
    console.log('✅ Connected.');

    const schemaDir = path.resolve(__dirname, '../schema');
    const files = fs.readdirSync(schemaDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    if (files.length === 0) {
      console.log('⚠️  No SQL files found in schema directory.');
      return;
    }

    for (const file of files) {
      const filePath = path.join(schemaDir, file);
      const sql = fs.readFileSync(filePath, 'utf-8');

      console.log(`🔄 Running migration: ${file}`);
      await pool.query(sql);
      console.log(`✅ Completed: ${file}`);
    }

    console.log('✅ All migrations completed successfully.');
  } catch (err) {
    console.error('❌ Migration failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

migrate();
