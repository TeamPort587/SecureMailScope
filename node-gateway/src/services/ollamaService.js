const axios = require('axios');
const env = require('../config/env');
const logger = require('../utils/logger');

/**
 * Ollama REST API client.
 *
 * Communicates with a locally running Ollama instance for LLM inference.
 * Follows the same HTTP client pattern as djangoClient.js.
 */

/**
 * Check whether Ollama is running and the configured model is available.
 *
 * @returns {Promise<{online: boolean, model: string, available: boolean}>}
 */
async function checkStatus() {
  try {
    const response = await axios.get(`${env.OLLAMA_BASE_URL}/api/tags`, {
      timeout: 5000,
    });

    const models = response.data?.models || [];
    const modelNames = models.map((m) => m.name);

    // Check for exact match or match without tag suffix
    const available = modelNames.some(
      (name) =>
        name === env.OLLAMA_MODEL ||
        name === `${env.OLLAMA_MODEL}:latest` ||
        name.startsWith(env.OLLAMA_MODEL)
    );

    return {
      online: true,
      model: env.OLLAMA_MODEL,
      available,
      models_loaded: modelNames,
    };
  } catch (err) {
    logger.warn('Ollama status check failed', {
      error: err.message,
      url: env.OLLAMA_BASE_URL,
    });

    return {
      online: false,
      model: env.OLLAMA_MODEL,
      available: false,
      models_loaded: [],
    };
  }
}

/**
 * Send a chat completion request to Ollama (non-streaming).
 *
 * @param {Array<{role: string, content: string}>} messages - Conversation messages
 * @param {object} [options]
 * @param {number} [options.temperature] - Override model temperature
 * @returns {Promise<{response: string, model: string, totalDuration: number}>}
 */
async function chat(messages, options = {}) {
  const payload = {
    model: env.OLLAMA_MODEL,
    messages,
    stream: false,
    options: {},
  };

  if (options.temperature !== undefined) {
    payload.options.temperature = options.temperature;
  }

  logger.info('Sending chat request to Ollama', {
    model: env.OLLAMA_MODEL,
    messageCount: messages.length,
    lastRole: messages[messages.length - 1]?.role,
  });

  try {
    const response = await axios.post(
      `${env.OLLAMA_BASE_URL}/api/chat`,
      payload,
      {
        timeout: env.OLLAMA_TIMEOUT_MS,
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const data = response.data;

    logger.info('Ollama chat response received', {
      model: data.model,
      totalDuration: data.total_duration
        ? `${(data.total_duration / 1e9).toFixed(2)}s`
        : 'unknown',
    });

    return {
      response: data.message?.content || '',
      model: data.model || env.OLLAMA_MODEL,
      totalDuration: data.total_duration || 0,
    };
  } catch (err) {
    if (err.code === 'ECONNABORTED') {
      logger.error('Ollama request timed out', {
        timeoutMs: env.OLLAMA_TIMEOUT_MS,
      });
      const timeoutErr = new Error(
        `AI copilot request timed out after ${env.OLLAMA_TIMEOUT_MS / 1000}s. The model may still be loading — try again in a moment.`
      );
      timeoutErr.statusCode = 504;
      timeoutErr.errorCode = 'COPILOT_TIMEOUT';
      timeoutErr.isOperational = true;
      throw timeoutErr;
    }

    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || !err.response) {
      logger.error('Ollama service unavailable', { error: err.message });
      const { CopilotUnavailableError } = require('../utils/errors');
      throw new CopilotUnavailableError();
    }

    logger.error('Ollama chat error', {
      error: err.message,
      status: err.response?.status,
    });
    throw err;
  }
}

/**
 * Send a streaming chat request to Ollama.
 *
 * Streams tokens via a callback function. Used for SSE delivery to clients.
 *
 * @param {Array<{role: string, content: string}>} messages
 * @param {function(string): void} onToken - Called with each token chunk
 * @param {function(): void} onDone - Called when stream completes
 * @returns {Promise<void>}
 */
async function chatStream(messages, onToken, onDone) {
  const payload = {
    model: env.OLLAMA_MODEL,
    messages,
    stream: true,
  };

  logger.info('Starting streaming chat with Ollama', {
    model: env.OLLAMA_MODEL,
    messageCount: messages.length,
  });

  const response = await axios.post(
    `${env.OLLAMA_BASE_URL}/api/chat`,
    payload,
    {
      timeout: env.OLLAMA_TIMEOUT_MS,
      headers: { 'Content-Type': 'application/json' },
      responseType: 'stream',
    }
  );

  return new Promise((resolve, reject) => {
    let buffer = '';

    response.data.on('data', (chunk) => {
      buffer += chunk.toString();

      // Ollama streams newline-delimited JSON
      const lines = buffer.split('\n');
      buffer = lines.pop(); // Keep incomplete line in buffer

      for (const line of lines) {
        if (!line.trim()) continue;

        try {
          const parsed = JSON.parse(line);

          if (parsed.message?.content) {
            onToken(parsed.message.content);
          }

          if (parsed.done) {
            onDone();
          }
        } catch (parseErr) {
          logger.warn('Failed to parse Ollama stream chunk', {
            error: parseErr.message,
          });
        }
      }
    });

    response.data.on('end', () => {
      // Process any remaining buffer
      if (buffer.trim()) {
        try {
          const parsed = JSON.parse(buffer);
          if (parsed.message?.content) {
            onToken(parsed.message.content);
          }
        } catch (_) {
          // Ignore
        }
      }
      resolve();
    });

    response.data.on('error', (err) => {
      logger.error('Ollama stream error', { error: err.message });
      reject(err);
    });
  });
}

module.exports = {
  checkStatus,
  chat,
  chatStream,
};
