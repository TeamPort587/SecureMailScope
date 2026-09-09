const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');

const SALT_ROUNDS = 12;

/**
 * Hash a plaintext password using bcrypt.
 * @param {string} plaintext
 * @returns {Promise<string>}
 */
async function hashPassword(plaintext) {
  return bcrypt.hash(plaintext, SALT_ROUNDS);
}

/**
 * Compare a plaintext password against a bcrypt hash.
 * @param {string} plaintext
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function comparePassword(plaintext, hash) {
  return bcrypt.compare(plaintext, hash);
}

/**
 * Calculate SHA-256 hash of a file.
 * @param {string} filePath - Absolute path to the file
 * @returns {Promise<string>} - Hex-encoded SHA-256 hash
 */
function calculateSHA256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

module.exports = {
  hashPassword,
  comparePassword,
  calculateSHA256,
};
