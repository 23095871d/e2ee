-- setup_database.sql
-- Server-side SQLite database schema for the Secure IM application.
-- This file can be imported to set up the database from scratch.
-- Usage: sqlite3 server.db < setup_database.sql

-- ============================================================
-- USERS TABLE
-- Stores registered user accounts with hashed passwords and OTP secrets.
-- Passwords are hashed using Argon2id (modern, memory-hard hash).
-- OTP secrets are stored server-side for TOTP verification during login.
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,        -- Argon2id hash (includes salt)
    otp_secret      TEXT    NOT NULL,        -- Base32-encoded TOTP secret
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active       BOOLEAN DEFAULT 1
);

-- ============================================================
-- USER PUBLIC KEYS TABLE
-- Stores each user's public keys for E2EE key exchange.
-- The server NEVER has access to private keys.
-- identity_public_key: X25519 public key for Diffie-Hellman key agreement
-- signing_public_key: Ed25519 public key for digital signatures
-- ============================================================
CREATE TABLE IF NOT EXISTS user_keys (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id                 INTEGER NOT NULL UNIQUE,
    identity_public_key     BLOB    NOT NULL,   -- X25519 public key (32 bytes)
    signing_public_key      BLOB    NOT NULL,   -- Ed25519 public key (32 bytes)
    uploaded_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- SESSIONS TABLE
-- Tracks active login sessions with expiring auth tokens.
-- Tokens are invalidated on logout or expiry.
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token       TEXT    UNIQUE NOT NULL,         -- Random session token
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL,             -- Token expiration time
    is_valid    BOOLEAN DEFAULT 1,              -- Set to 0 on logout
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- FRIEND REQUESTS TABLE
-- Manages the friend request workflow: send -> accept/decline/cancel.
-- Status can be: 'pending', 'accepted', 'declined', 'cancelled'
-- ============================================================
CREATE TABLE IF NOT EXISTS friend_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id   INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    status      TEXT    DEFAULT 'pending',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- FRIENDS TABLE
-- Stores established friendships (bidirectional).
-- When a friend request is accepted, two rows are inserted
-- (one for each direction) so lookups are fast.
-- ============================================================
CREATE TABLE IF NOT EXISTS friends (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    friend_id   INTEGER NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, friend_id)
);

-- ============================================================
-- BLOCKED USERS TABLE
-- Users can block other users to prevent messages and friend requests.
-- ============================================================
CREATE TABLE IF NOT EXISTS blocked_users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id  INTEGER NOT NULL,
    blocked_id  INTEGER NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(blocker_id, blocked_id)
);

-- ============================================================
-- OFFLINE MESSAGES TABLE
-- Stores encrypted messages for users who are currently offline.
-- The server only stores ciphertext -- it cannot decrypt these.
-- Messages with a TTL are automatically cleaned up after expiry.
-- ============================================================
CREATE TABLE IF NOT EXISTS offline_messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id       INTEGER NOT NULL,
    receiver_id     INTEGER NOT NULL,
    ciphertext      TEXT    NOT NULL,       -- Base64-encoded encrypted message
    nonce           TEXT    NOT NULL,       -- Base64-encoded nonce for AES-GCM
    ephemeral_key   TEXT,                  -- Base64-encoded ephemeral public key (for session init)
    message_counter INTEGER NOT NULL,      -- Counter for replay protection
    ttl             INTEGER,               -- Time-to-live in seconds (NULL = no expiry)
    associated_data TEXT    NOT NULL,       -- Base64-encoded AD used in encryption
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP,             -- When this message should be deleted
    delivered       BOOLEAN DEFAULT 0,
    FOREIGN KEY (sender_id)   REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================
-- RATE LIMITING TABLE
-- Tracks actions for rate limiting (login attempts, registrations, etc.)
-- to prevent brute-force and spam attacks.
-- ============================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier      TEXT    NOT NULL,       -- IP address or username
    action          TEXT    NOT NULL,       -- 'login', 'register', 'friend_request'
    attempt_time    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- INDEXES for faster lookups
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_friends_user ON friends(user_id);
CREATE INDEX IF NOT EXISTS idx_offline_receiver ON offline_messages(receiver_id);
CREATE INDEX IF NOT EXISTS idx_offline_expires ON offline_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_action ON rate_limits(identifier, action);
CREATE INDEX IF NOT EXISTS idx_friend_requests_receiver ON friend_requests(receiver_id, status);
CREATE INDEX IF NOT EXISTS idx_blocked_users ON blocked_users(blocker_id, blocked_id);
