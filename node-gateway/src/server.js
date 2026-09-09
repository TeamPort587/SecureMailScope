const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const env = require('./config/env');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const rateLimiter = require('./middleware/rateLimit');

// Route imports
const healthRoutes = require('./routes/health');
const authRoutes = require('./routes/auth');
const analyzeRoutes = require('./routes/analyze');
const analysesRoutes = require('./routes/analyses');

const app = express();

// ---------------------------------------------------------------------------
// Global Middleware
// ---------------------------------------------------------------------------

// Security headers
app.use(helmet());

// CORS — configurable in production
app.use(cors({
  origin: env.NODE_ENV === 'production' ? false : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting
app.use(rateLimiter);

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// Ensure upload directory exists
// ---------------------------------------------------------------------------
const uploadDir = path.resolve(env.UPLOAD_DIR);
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  logger.info('Created upload directory', { path: uploadDir });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.use('/api/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/analyze', analyzeRoutes);
app.use('/api/analyses', analysesRoutes);

// ---------------------------------------------------------------------------
// 404 catch-all
// ---------------------------------------------------------------------------
app.use((_req, res) => {
  res.status(404).json({
    status: 'error',
    error: {
      code: 'NOT_FOUND',
      message: 'The requested endpoint does not exist.',
    },
  });
});

// ---------------------------------------------------------------------------
// Global Error Handler (must be last)
// ---------------------------------------------------------------------------
app.use(errorHandler);

// ---------------------------------------------------------------------------
// Start server (only when not under test)
// ---------------------------------------------------------------------------
if (process.env.NODE_ENV !== 'test') {
  app.listen(env.PORT, () => {
    logger.info(`Gateway server started`, {
      port: env.PORT,
      env: env.NODE_ENV,
      mockDjango: env.USE_MOCK_DJANGO,
    });
  });
}

module.exports = app;
