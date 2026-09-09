const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/auth');
const upload = require('../middleware/upload');
const { validateUpload } = require('../validators/uploadSchema');
const { analyze } = require('../controllers/analyzeController');

/**
 * POST /api/analyze
 *
 * Protected. Multipart upload of a PCAP file for analysis.
 */
router.post(
  '/',
  authenticate,
  upload.single('file'),
  validateUpload,
  analyze
);

module.exports = router;
