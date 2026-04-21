-- =============================================================================
-- V1__create_users_table.sql
-- Creates the core identity table for the authentication system (DT 3.1.20).
-- Primary key: UUID stored as VARCHAR(36) (DT 3.1.21).
-- Role: stored as a string enum (DT 3.2.9).
-- =============================================================================

CREATE TABLE users (
    id       VARCHAR(36)  NOT NULL,
    email    VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role     VARCHAR(50)  NOT NULL DEFAULT 'USER',

    CONSTRAINT pk_users        PRIMARY KEY (id),
    CONSTRAINT uq_users_email  UNIQUE (email)
);
