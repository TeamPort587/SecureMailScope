const jwt = require('jsonwebtoken');
const env = require('../config/env');
const { hashPassword, comparePassword } = require('../utils/hash');
const db = require('../services/databaseService');
const { UnauthorizedError, DuplicateEmailError } = require('../utils/errors');
const logger = require('../utils/logger');

/**
 * POST /api/auth/register
 */
async function register(req, res, next) {
  try {
    const { email, password } = req.body;

    const passwordHash = await hashPassword(password);

    let user;
    try {
      user = await db.createUser(email, passwordHash);
    } catch (err) {
      // PostgreSQL unique violation
      if (err.code === '23505') {
        throw new DuplicateEmailError();
      }
      throw err;
    }

    logger.info('User registered', { userId: user.id });

    res.status(201).json({
      status: 'success',
      user: {
        id: user.id,
        email: user.email,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    next(err);
  }
}

/**
 * POST /api/auth/login
 */
async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const user = await db.findUserByEmail(email);

    if (!user) {
      logger.info('Login failed — user not found', { email });
      throw new UnauthorizedError('Invalid email or password.');
    }

    const valid = await comparePassword(password, user.password_hash);

    if (!valid) {
      logger.info('Login failed — invalid password', { userId: user.id });
      throw new UnauthorizedError('Invalid email or password.');
    }

    // Sign JWT with minimal payload
    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
      },
      env.JWT_SECRET,
      { expiresIn: env.JWT_EXPIRES_IN }
    );

    logger.info('User login success', { userId: user.id });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  register,
  login,
};
