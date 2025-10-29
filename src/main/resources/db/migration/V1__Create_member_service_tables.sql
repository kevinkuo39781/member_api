-- Member Service Database Schema
-- Based on dev.md specifications

-- Enable CITEXT extension for case-insensitive email
CREATE EXTENSION IF NOT EXISTS citext;

-- 1. users (core table)
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email CITEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_algo TEXT NOT NULL DEFAULT 'argon2id',
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    status SMALLINT NOT NULL DEFAULT 2, -- 2=pending_activation, 1=active, 0=locked
    mfa_method TEXT NOT NULL DEFAULT 'email_otp',
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

-- 2. email_verification_tokens (activation emails)
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,            -- only store hash
    expires_at TIMESTAMPTZ NOT NULL,     -- default 24h
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX ON email_verification_tokens(user_id);
CREATE INDEX ON email_verification_tokens(expires_at);

-- 3. email_otps (Email 2FA, one-time passwords)
CREATE TABLE email_otps (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,             -- 6-digit code hash
    purpose TEXT NOT NULL,               -- 'login_2fa'
    retry_count SMALLINT NOT NULL DEFAULT 0,
    max_retries SMALLINT NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,     -- 10 minutes
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ
);

CREATE INDEX ON email_otps(user_id);
CREATE INDEX ON email_otps(expires_at);

-- 4. refresh_tokens (Opaque Refresh, server-side hash storage)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,     -- e.g., 30 days
    rotated_from UUID,
    revoked_at TIMESTAMPTZ,
    user_agent TEXT,
    ip_addr INET
);

CREATE INDEX ON refresh_tokens(user_id);
CREATE INDEX ON refresh_tokens(expires_at);

-- 5. audit_logins (audit records, can be partitioned by month if needed)
CREATE TABLE audit_logins (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,                 -- password_ok / otp_sent / otp_verified / login_success
    success BOOLEAN NOT NULL,
    ip_addr INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);