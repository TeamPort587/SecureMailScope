const ollamaService = require('../services/ollamaService');
const promptService = require('../services/copilotPromptService');
const db = require('../services/databaseService');
const logger = require('../utils/logger');
const {
  CopilotUnavailableError,
  AnalysisNotFoundError,
  ForbiddenError,
  ValidationError,
} = require('../utils/errors');

// ============================================================================
// GET /api/copilot/status
// ============================================================================

/**
 * Returns the current status of the AI Copilot (Ollama availability).
 */
async function getStatus(req, res, next) {
  try {
    const status = await ollamaService.checkStatus();

    res.json({
      status: status.online ? 'online' : 'offline',
      model: status.model,
      model_available: status.available,
    });
  } catch (err) {
    next(err);
  }
}

// ============================================================================
// POST /api/copilot/suggestions
// ============================================================================

/**
 * Generate context-aware suggested questions for a given analysis.
 *
 * Body: { analysisId: string }
 * Returns: { suggestions: string[] }
 */
async function getSuggestions(req, res, next) {
  try {
    const { analysisId } = req.body;
    const userId = req.user.id;

    if (!analysisId) {
      throw new ValidationError('analysisId is required.');
    }

    // Fetch analysis (with ownership check)
    const analysis = await db.getAnalysisById(analysisId, userId);

    if (!analysis) {
      throw new AnalysisNotFoundError();
    }

    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to access this analysis.');
    }

    // Fetch full data for findings
    const fullData = await db.getFullAnalysis(analysisId);

    // Generate suggestions
    const suggestions = promptService.generateSuggestedQuestions(
      fullData.findings,
      fullData.risk
    );

    res.json({ suggestions });
  } catch (err) {
    next(err);
  }
}

// ============================================================================
// POST /api/copilot/chat
// ============================================================================

/**
 * Chat with the AI Copilot, grounded in analysis data.
 *
 * Body: {
 *   message: string,        // User's question (required)
 *   analysisId: string,     // Analysis to ground responses in (required)
 *   history?: Array<{role, content}>, // Prior conversation turns
 *   stream?: boolean        // If true, stream via SSE (default false)
 * }
 *
 * Returns (non-streaming): { response, model, source }
 * Returns (streaming):     text/event-stream with SSE chunks
 */
async function chat(req, res, next) {
  try {
    const { message, analysisId, history = [], stream = false } = req.body;
    const userId = req.user.id;

    // --- Validate ---
    if (!message || typeof message !== 'string' || !message.trim()) {
      throw new ValidationError('message is required and must be a non-empty string.');
    }

    if (!analysisId) {
      throw new ValidationError('analysisId is required.');
    }

    // --- Fetch analysis data ---
    const analysis = await db.getAnalysisById(analysisId, userId);

    if (!analysis) {
      throw new AnalysisNotFoundError();
    }

    if (analysis.forbidden) {
      throw new ForbiddenError('You do not have permission to access this analysis.');
    }

    const fullData = await db.getFullAnalysis(analysisId);

    // --- Check Ollama status ---
    const status = await ollamaService.checkStatus();

    if (!status.online) {
      throw new CopilotUnavailableError(
        'The AI copilot service is not running. Please ensure Ollama is started.'
      );
    }

    // --- Build grounded prompt ---
    const systemPrompt = promptService.buildSystemPrompt({
      analysis: {
        filename: analysis.filename,
        status: analysis.status,
      },
      sessions: fullData.sessions,
      findings: fullData.findings,
      risk: fullData.risk,
      recommendations: fullData.recommendations,
    });

    // --- Construct messages array ---
    const messages = [
      { role: 'system', content: systemPrompt },
    ];

    // Add conversation history (limit to last 10 turns to stay within context window)
    const trimmedHistory = history.slice(-10);
    for (const turn of trimmedHistory) {
      if (turn.role && turn.content) {
        messages.push({
          role: turn.role === 'user' ? 'user' : 'assistant',
          content: turn.content,
        });
      }
    }

    // Add current message
    messages.push({ role: 'user', content: message.trim() });

    logger.info('Copilot chat request', {
      analysisId,
      userId,
      messageLength: message.length,
      historyTurns: trimmedHistory.length,
      stream,
    });

    // --- Stream or full response ---
    if (stream) {
      return await handleStreamResponse(res, messages);
    }

    return await handleFullResponse(res, messages);
  } catch (err) {
    // Log the real error for debugging
    logger.error('Copilot chat error', {
      errorMessage: err.message,
      errorCode: err.errorCode || err.code,
      errorName: err.name,
    });

    // If it's already an AppError, pass it through
    if (err.isOperational) {
      return next(err);
    }

    // Wrap unknown errors as CopilotUnavailableError
    return next(new CopilotUnavailableError(
      `AI copilot error: ${err.message || 'An unexpected error occurred.'}`
    ));
  }
}

/**
 * Handle non-streaming chat response.
 */
async function handleFullResponse(res, messages) {
  const result = await ollamaService.chat(messages);

  res.json({
    response: result.response,
    model: result.model,
    source: 'ollama',
  });
}

/**
 * Handle streaming chat response via Server-Sent Events.
 */
async function handleStreamResponse(res, messages) {
  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  // Send initial event
  res.write(`data: ${JSON.stringify({ type: 'start', model: require('../config/env').OLLAMA_MODEL })}\n\n`);

  try {
    await ollamaService.chatStream(
      messages,
      // onToken
      (token) => {
        res.write(`data: ${JSON.stringify({ type: 'token', content: token })}\n\n`);
      },
      // onDone
      () => {
        res.write(`data: ${JSON.stringify({ type: 'done', source: 'ollama' })}\n\n`);
        res.end();
      }
    );
  } catch (err) {
    logger.error('Copilot stream error', { error: err.message });
    res.write(
      `data: ${JSON.stringify({ type: 'error', message: 'Stream interrupted' })}\n\n`
    );
    res.end();
  }
}

module.exports = {
  getStatus,
  getSuggestions,
  chat,
};
