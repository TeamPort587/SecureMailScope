const { AppError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * Global error handler middleware.
 *
 * Converts all errors to the standard response format:
 *   { status: "error", error: { code, message } }
 *
 * Never exposes stack traces, internal paths, or implementation details.
 */
function errorHandler(err, req, res, _next) {
  // Log the full error internally
  logger.error(`${err.errorCode || 'INTERNAL_ERROR'}: ${err.message}`, {
    path: req.path,
    method: req.method,
    ...(err.stack && process.env.NODE_ENV !== 'production' ? { stack: err.stack } : {}),
  });

  // Multer file size error
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      status: 'error',
      error: {
        code: 'FILE_TOO_LARGE',
        message: 'The uploaded file exceeds the maximum allowed size.',
      },
    });
  }

  // Multer unexpected field
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({
      status: 'error',
      error: {
        code: 'INVALID_FILE',
        message: 'Unexpected file field in upload.',
      },
    });
  }

  // Known operational errors
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      status: 'error',
      error: {
        code: err.errorCode,
        message: err.message,
      },
    });
  }

  // JSON parse error
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      status: 'error',
      error: {
        code: 'INVALID_REQUEST',
        message: 'Request body contains invalid JSON.',
      },
    });
  }

  // Unknown / unexpected errors — never expose details
  return res.status(500).json({
    status: 'error',
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    },
  });
}

module.exports = errorHandler;
