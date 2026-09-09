const { z } = require('zod');

/**
 * Zod schemas for authentication request validation.
 */

const registerSchema = z.object({
  email: z
    .string({ required_error: 'Email is required.' })
    .email('A valid email address is required.')
    .max(255, 'Email must be 255 characters or fewer.')
    .transform((val) => val.toLowerCase().trim()),
  password: z
    .string({ required_error: 'Password is required.' })
    .min(8, 'Password must be at least 8 characters.')
    .max(128, 'Password must be 128 characters or fewer.'),
});

const loginSchema = z.object({
  email: z
    .string({ required_error: 'Email is required.' })
    .email('A valid email address is required.')
    .transform((val) => val.toLowerCase().trim()),
  password: z
    .string({ required_error: 'Password is required.' })
    .min(1, 'Password is required.'),
});

module.exports = {
  registerSchema,
  loginSchema,
};
