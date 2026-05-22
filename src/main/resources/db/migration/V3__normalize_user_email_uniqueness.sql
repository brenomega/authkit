-- Normalize existing emails and enforce case-insensitive uniqueness.

UPDATE users
SET email = lower(trim(email));

CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));
