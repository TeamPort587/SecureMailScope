/**
 * Simple structured logger.
 *
 * Logs structured JSON in production, human-readable in development.
 * NEVER logs passwords, JWTs, raw PCAP contents, or SMTP/IMAP/POP3 credentials.
 */

const env = require('../config/env');

const LOG_LEVELS = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

const currentLevel = env.NODE_ENV === 'production' ? 'info' : 'debug';

function shouldLog(level) {
  return LOG_LEVELS[level] <= LOG_LEVELS[currentLevel];
}

function formatMessage(level, message, meta = {}) {
  const timestamp = new Date().toISOString();

  if (env.NODE_ENV === 'production') {
    return JSON.stringify({ timestamp, level, message, ...meta });
  }

  const metaStr = Object.keys(meta).length > 0
    ? ` ${JSON.stringify(meta)}`
    : '';
  return `[${timestamp}] ${level.toUpperCase()} ${message}${metaStr}`;
}

const logger = {
  error(message, meta = {}) {
    if (shouldLog('error')) {
      console.error(formatMessage('error', message, meta));
    }
  },

  warn(message, meta = {}) {
    if (shouldLog('warn')) {
      console.warn(formatMessage('warn', message, meta));
    }
  },

  info(message, meta = {}) {
    if (shouldLog('info')) {
      console.log(formatMessage('info', message, meta));
    }
  },

  debug(message, meta = {}) {
    if (shouldLog('debug')) {
      console.log(formatMessage('debug', message, meta));
    }
  },
};

module.exports = logger;
