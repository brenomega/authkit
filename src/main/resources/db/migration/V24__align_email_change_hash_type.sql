-- Hibernate maps this bounded string as VARCHAR; preserve all existing hashes
-- while correcting the V17 fixed-width type for production schema validation.
ALTER TABLE users
    ALTER COLUMN email_change_token_hash TYPE VARCHAR(64)
    USING email_change_token_hash::VARCHAR(64);
