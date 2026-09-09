const rateLimit = require('express-rate-limit');
const env = require('../config/env');

/**
 * Rate limiter middleware.
 *
 * Configurable window and max requests via environment variables.
 * Returns standard error format on limit exceeded.
 */
const limiter = rateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      status: 'error',
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please try again later.',
      },
    });
  },
});

module.exports = limiter;
