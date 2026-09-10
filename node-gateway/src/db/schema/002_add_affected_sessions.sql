-- Add affected_sessions to recommendations table
ALTER TABLE recommendations ADD COLUMN IF NOT EXISTS affected_sessions JSONB DEFAULT '[]'::jsonb;
