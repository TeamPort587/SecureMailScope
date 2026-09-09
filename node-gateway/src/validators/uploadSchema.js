const { InvalidFileError } = require('../utils/errors');

/**
 * Post-upload validation middleware.
 *
 * Runs after Multer has processed the upload.
 * Validates that a file was actually received and is non-empty.
 */
function validateUpload(req, _res, next) {
  if (!req.file) {
    return next(new InvalidFileError('No file was uploaded. Please attach a PCAP file.'));
  }

  if (req.file.size === 0) {
    return next(new InvalidFileError('The uploaded file is empty.'));
  }

  next();
}

module.exports = { validateUpload };
