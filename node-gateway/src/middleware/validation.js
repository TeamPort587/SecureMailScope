const { ZodError } = require('zod');

/**
 * Generic Zod validation middleware factory.
 *
 * Usage:
 *   router.post('/register', validate(registerSchema), controller)
 *
 * Validates req.body against the provided Zod schema.
 * On failure, returns 422 with validation error details.
 *
 * @param {import('zod').ZodSchema} schema
 */
function validate(schema) {
  return (req, res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        const messages = err.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        }));

        return res.status(422).json({
          status: 'error',
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request validation failed.',
            details: messages,
          },
        });
      }
      next(err);
    }
  };
}

module.exports = validate;
