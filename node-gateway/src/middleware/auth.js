const jwt = require('jsonwebtoken');
const env = require('../config/env');
const { UnauthorizedError } = require('../utils/errors');

/**
 * JWT authentication middleware.
 *
 * 1. Reads Authorization header
 * 2. Confirms Bearer token exists
 * 3. Verifies JWT signature
 * 4. Extracts user identity
 * 5. Attaches authenticated user to req.user
 * 6. Rejects invalid/expired tokens with 401
 */
function authenticate(req, _res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedError('Authentication is required.');
    }

    const parts = authHeader.split(' ');

    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new UnauthorizedError('Invalid authorization format. Use: Bearer <token>');
    }

    const token = parts[1];
    const decoded = jwt.verify(token, env.JWT_SECRET);

    // Attach user identity to request
    req.user = {
      id: decoded.sub,
      email: decoded.email,
    };

    next();
  } catch (err) {
    if (err instanceof UnauthorizedError) {
      return next(err);
    }

    if (err.name === 'JsonWebTokenError') {
      return next(new UnauthorizedError('Invalid authentication token.'));
    }

    if (err.name === 'TokenExpiredError') {
      return next(new UnauthorizedError('Authentication token has expired.'));
    }

    return next(new UnauthorizedError());
  }
}

module.exports = authenticate;
