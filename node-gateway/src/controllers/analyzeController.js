const { processUpload } = require('../services/analysisService');
const logger = require('../utils/logger');

/**
 * POST /api/analyze
 *
 * Upload a PCAP file for analysis.
 * Authentication required. File validated by upload middleware.
 */
async function analyze(req, res, next) {
  try {
    const userId = req.user.id;
    const file = req.file;

    logger.info('Analysis upload received', {
      userId,
      filename: file.originalname,
      size: file.size,
    });

    const result = await processUpload(userId, file);

    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
}

module.exports = { analyze };
