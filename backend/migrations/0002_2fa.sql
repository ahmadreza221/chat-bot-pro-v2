-- +migrate Up
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret TEXT,
    ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- +migrate Down
ALTER TABLE users
    DROP COLUMN IF EXISTS totp_secret,
    DROP COLUMN IF EXISTS totp_enabled; 