/**
 * Application error classes with standardized error codes.
 *
 * All error codes align with the SecureMailScope error specification.
 * These errors are caught by the global error handler and converted
 * to the standard { status: "error", error: { code, message } } format.
 */

class AppError extends Error {
  /**
   * @param {string} message - Human-readable error description
   * @param {number} statusCode - HTTP status code
   * @param {string} errorCode - Machine-readable error code
   */
  constructor(message, statusCode, errorCode) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

class InvalidFileError extends AppError {
  constructor(message = 'The uploaded file is not valid.') {
    super(message, 400, 'INVALID_FILE');
  }
}

class FileTooLargeError extends AppError {
  constructor(message = 'The uploaded file exceeds the maximum allowed size.') {
    super(message, 413, 'FILE_TOO_LARGE');
  }
}

class UnauthorizedError extends AppError {
  constructor(message = 'Authentication is required.') {
    super(message, 401, 'UNAUTHORIZED');
  }
}

class ForbiddenError extends AppError {
  constructor(message = 'You do not have permission to access this resource.') {
    super(message, 403, 'FORBIDDEN');
  }
}

class AnalysisNotFoundError extends AppError {
  constructor(message = 'The requested analysis was not found.') {
    super(message, 404, 'ANALYSIS_NOT_FOUND');
  }
}

class DjangoUnavailableError extends AppError {
  constructor(message = 'The analysis service is currently unavailable.') {
    super(message, 502, 'DJANGO_UNAVAILABLE');
  }
}

class AnalysisFailedError extends AppError {
  constructor(message = 'The analysis could not be completed.') {
    super(message, 500, 'ANALYSIS_FAILED');
  }
}

class InvalidAnalysisResponseError extends AppError {
  constructor(message = 'The analysis service returned an invalid response.') {
    super(message, 502, 'INVALID_ANALYSIS_RESPONSE');
  }
}

class DatabaseError extends AppError {
  constructor(message = 'A database error occurred.') {
    super(message, 500, 'DATABASE_ERROR');
  }
}

class AnalysisTimeoutError extends AppError {
  constructor(message = 'The analysis service timed out.') {
    super(message, 504, 'ANALYSIS_TIMEOUT');
  }
}

class ValidationError extends AppError {
  constructor(message = 'Request validation failed.') {
    super(message, 422, 'VALIDATION_ERROR');
  }
}

class DuplicateEmailError extends AppError {
  constructor(message = 'An account with this email already exists.') {
    super(message, 409, 'DUPLICATE_EMAIL');
  }
}

class CopilotUnavailableError extends AppError {
  constructor(message = 'The AI copilot service is currently unavailable.') {
    super(message, 503, 'COPILOT_UNAVAILABLE');
  }
}

class SessionNotFoundError extends AppError {
  constructor(message = 'The requested session was not found.') {
    super(message, 404, 'SESSION_NOT_FOUND');
  }
}

class SessionExportError extends AppError {
  constructor(message = 'Failed to export session capture.') {
    super(message, 500, 'SESSION_EXPORT_FAILED');
  }
}

class SourceFileNotFoundError extends AppError {
  constructor(message = 'The source capture file is no longer available on disk.') {
    super(message, 404, 'SOURCE_FILE_NOT_FOUND');
  }
}

module.exports = {
  AppError,
  InvalidFileError,
  FileTooLargeError,
  UnauthorizedError,
  ForbiddenError,
  AnalysisNotFoundError,
  SessionNotFoundError,
  SessionExportError,
  SourceFileNotFoundError,
  DjangoUnavailableError,
  AnalysisFailedError,
  InvalidAnalysisResponseError,
  DatabaseError,
  AnalysisTimeoutError,
  ValidationError,
  DuplicateEmailError,
  CopilotUnavailableError,
};

