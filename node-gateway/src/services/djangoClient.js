const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const env = require('../config/env');
const logger = require('../utils/logger');
const { DjangoUnavailableError, AnalysisTimeoutError } = require('../utils/errors');
const { getMockAnalysisResponse } = require('./mockDjango');

/**
 * Send a PCAP file to the Django Analysis API for processing.
 *
 * @param {string} filePath - Absolute path to the uploaded PCAP file
 * @param {object} metadata - Analysis metadata to send along
 * @param {string} metadata.analysis_id
 * @param {string} metadata.filename - Original filename
 * @param {string} metadata.sha256
 * @param {number} metadata.size_bytes
 * @returns {Promise<object>} - Parsed analysis response JSON
 */
async function analyzeFile(filePath, metadata) {
  // Use mock in development when configured
  if (env.USE_MOCK_DJANGO) {
    logger.info('Using mock Django response', { analysisId: metadata.analysis_id });
    // Simulate small network delay
    await new Promise((resolve) => setTimeout(resolve, 500));
    return getMockAnalysisResponse(metadata);
  }

  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));
  form.append('analysis_id', metadata.analysis_id);
  form.append('filename', metadata.filename);
  form.append('sha256', metadata.sha256);
  form.append('size_bytes', String(metadata.size_bytes));
  form.append('requested_at', new Date().toISOString());
  form.append('analysis_version', '1.0.0');

  const url = `${env.DJANGO_BASE_URL}/internal/analyze`;

  logger.info('Sending PCAP to Django', {
    analysisId: metadata.analysis_id,
    url,
  });

  try {
    const response = await axios.post(url, form, {
      headers: {
        ...form.getHeaders(),
        'X-Internal-Key': env.DJANGO_INTERNAL_KEY,
      },
      timeout: env.DJANGO_TIMEOUT_MS,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    });

    logger.info('Django response received', {
      analysisId: metadata.analysis_id,
      status: response.status,
    });

    return response.data;
  } catch (err) {
    if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
      logger.error('Django request timed out', {
        analysisId: metadata.analysis_id,
        timeoutMs: env.DJANGO_TIMEOUT_MS,
      });
      throw new AnalysisTimeoutError();
    }

    if (err.code === 'ECONNREFUSED' || err.code === 'ENOTFOUND' || !err.response) {
      logger.error('Django service unavailable', {
        analysisId: metadata.analysis_id,
        error: err.message,
      });
      throw new DjangoUnavailableError();
    }

    // Django responded with an error status
    logger.error('Django returned error', {
      analysisId: metadata.analysis_id,
      status: err.response?.status,
      data: err.response?.data,
    });
    throw new DjangoUnavailableError(
      `Analysis service returned status ${err.response?.status}.`
    );
  }
}

module.exports = { analyzeFile };
