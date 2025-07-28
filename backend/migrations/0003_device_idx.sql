-- +migrate Up
CREATE UNIQUE INDEX IF NOT EXISTS device_fingerprints_user_fingerprint_idx
    ON device_fingerprints(user_id, fingerprint);

-- +migrate Down
DROP INDEX IF EXISTS device_fingerprints_user_fingerprint_idx; 