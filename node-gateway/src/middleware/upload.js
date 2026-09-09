const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const env = require('../config/env');
const { InvalidFileError } = require('../utils/errors');

/**
 * Supported PCAP file extensions.
 */
const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

/**
 * Multer storage configuration.
 *
 * - Saves to configurable UPLOAD_DIR
 * - Uses UUID filenames to prevent path traversal and collision
 * - Preserves original extension for downstream use
 */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, path.resolve(env.UPLOAD_DIR));
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  },
});

/**
 * File filter — reject unsupported extensions.
 */
function fileFilter(_req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();

  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(
      new InvalidFileError(
        `Unsupported file type "${ext}". Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`
      ),
      false
    );
  }

  cb(null, true);
}

/**
 * Configured Multer upload middleware.
 *
 * Expects a single file field named "file".
 * Enforces MAX_UPLOAD_SIZE_MB from environment.
 */
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: env.MAX_UPLOAD_SIZE_MB * 1024 * 1024,
    files: 1,
  },
});

module.exports = upload;
