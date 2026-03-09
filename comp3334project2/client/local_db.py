"""
local_db.py - Client-side local database for the Secure IM application.

This module manages the client's local SQLite database which stores:
- Identity keys (encrypted at rest with user's password)
- Contact information and their public keys
- Session state for E2EE conversations (chain keys, counters)
- Message history
- Seen message counters for replay protection

Security considerations:
- Private keys are encrypted before storage using AES-256-GCM
  with a key derived from the user's password
- Each user gets their own database file (username.db)
- The database is local only -- never synced to the server
"""

import os
import json
import sqlite3
import datetime


# ============================================================
# Database path and connection
# ============================================================

def get_db_path(username):
    """Get the path to a user's local database file."""
    # Store in a 'data' directory relative to the client folder
    data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, f"{username}_local.db")


def get_db(username):
    """Get a connection to the user's local database."""
    db_path = get_db_path(username)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_local_db(username):
    """
    Initialize the local database schema.
    Creates all necessary tables if they don't exist.
    """
    conn = get_db(username)

    conn.executescript("""
        -- Identity keys (our own keypairs, encrypted at rest)
        CREATE TABLE IF NOT EXISTS identity_keys (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_private_key    TEXT NOT NULL,   -- JSON: encrypted key data
            identity_public_key     BLOB NOT NULL,   -- raw public key bytes
            signing_private_key     TEXT NOT NULL,   -- JSON: encrypted key data
            signing_public_key      BLOB NOT NULL    -- raw public key bytes
        );

        -- Contacts (friends and their public keys)
        CREATE TABLE IF NOT EXISTS contacts (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            username                TEXT UNIQUE NOT NULL,
            identity_public_key     BLOB,           -- their X25519 public key
            signing_public_key      BLOB,           -- their Ed25519 public key
            fingerprint             TEXT,           -- safety number for verification
            is_verified             BOOLEAN DEFAULT 0,  -- user manually verified
            is_blocked              BOOLEAN DEFAULT 0,
            added_at                TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- E2EE session state for each conversation
        CREATE TABLE IF NOT EXISTS sessions (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_username        TEXT UNIQUE NOT NULL,
            shared_secret           BLOB NOT NULL,
            sending_chain_key       BLOB NOT NULL,
            receiving_chain_key     BLOB NOT NULL,
            send_counter            INTEGER DEFAULT 0,
            recv_counter            INTEGER DEFAULT 0,
            ephemeral_public_key    BLOB,   -- our ephemeral key (if we initiated)
            is_established          BOOLEAN DEFAULT 0,  -- both sides have keys
            established_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (contact_username) REFERENCES contacts(username)
        );

        -- Message history
        CREATE TABLE IF NOT EXISTS messages (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_username    TEXT NOT NULL,
            sender              TEXT NOT NULL,       -- 'me' or the contact's username
            content             TEXT NOT NULL,       -- decrypted plaintext
            timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status              TEXT DEFAULT 'sent', -- sent, delivered
            ttl                 INTEGER,             -- seconds until self-destruct
            expires_at          TIMESTAMP,           -- when to delete this message
            message_counter     INTEGER NOT NULL,
            is_incoming         BOOLEAN NOT NULL,    -- 1 = received, 0 = sent
            FOREIGN KEY (contact_username) REFERENCES contacts(username)
        );

        -- Seen message counters for replay protection (R9, R22)
        -- We track which counters we've already processed per contact
        CREATE TABLE IF NOT EXISTS seen_counters (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_username    TEXT NOT NULL,
            message_counter     INTEGER NOT NULL,
            seen_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(contact_username, message_counter)
        );

        -- Indexes for faster lookups
        CREATE INDEX IF NOT EXISTS idx_messages_contact 
            ON messages(contact_username);
        CREATE INDEX IF NOT EXISTS idx_messages_expires 
            ON messages(expires_at);
        CREATE INDEX IF NOT EXISTS idx_seen_counters 
            ON seen_counters(contact_username, message_counter);
    """)

    conn.commit()
    conn.close()


# ============================================================
# Identity key management
# ============================================================

def store_identity_keys(username, identity_priv_encrypted, identity_pub,
                        signing_priv_encrypted, signing_pub):
    """
    Store our identity keypairs (private keys encrypted).
    
    Args:
        username: our username (for DB file selection)
        identity_priv_encrypted: dict with salt/nonce/ciphertext (JSON serialized)
        identity_pub: raw X25519 public key bytes
        signing_priv_encrypted: dict with salt/nonce/ciphertext (JSON serialized)
        signing_pub: raw Ed25519 public key bytes
    """
    conn = get_db(username)
    # Clear any existing keys (we only store one identity)
    conn.execute("DELETE FROM identity_keys")
    conn.execute(
        """INSERT INTO identity_keys 
        (identity_private_key, identity_public_key, signing_private_key, signing_public_key)
        VALUES (?, ?, ?, ?)""",
        (json.dumps(identity_priv_encrypted), identity_pub,
         json.dumps(signing_priv_encrypted), signing_pub)
    )
    conn.commit()
    conn.close()


def get_identity_keys(username):
    """
    Retrieve stored identity keys.
    Returns dict with all key fields, or None if not found.
    Private keys are still encrypted -- caller must decrypt them.
    """
    conn = get_db(username)
    row = conn.execute("SELECT * FROM identity_keys LIMIT 1").fetchone()
    conn.close()
    if row is None:
        return None

    return {
        "identity_private_key": json.loads(row["identity_private_key"]),
        "identity_public_key": bytes(row["identity_public_key"]),
        "signing_private_key": json.loads(row["signing_private_key"]),
        "signing_public_key": bytes(row["signing_public_key"]),
    }


# ============================================================
# Contact management
# ============================================================

def add_contact(username, contact_username, identity_pub=None,
                signing_pub=None, fingerprint=None):
    """Add or update a contact."""
    conn = get_db(username)
    try:
        conn.execute(
            """INSERT INTO contacts (username, identity_public_key, signing_public_key, fingerprint)
            VALUES (?, ?, ?, ?)""",
            (contact_username, identity_pub, signing_pub, fingerprint)
        )
    except sqlite3.IntegrityError:
        # Contact already exists -- update their keys
        conn.execute(
            """UPDATE contacts 
            SET identity_public_key = ?, signing_public_key = ?, fingerprint = ?
            WHERE username = ?""",
            (identity_pub, signing_pub, fingerprint, contact_username)
        )
    conn.commit()
    conn.close()


def get_contact(username, contact_username):
    """Get a specific contact's info."""
    conn = get_db(username)
    row = conn.execute(
        "SELECT * FROM contacts WHERE username = ?",
        (contact_username,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    # Convert memoryview to bytes for key fields
    if result.get("identity_public_key"):
        result["identity_public_key"] = bytes(result["identity_public_key"])
    if result.get("signing_public_key"):
        result["signing_public_key"] = bytes(result["signing_public_key"])
    return result


def get_all_contacts(username):
    """Get all contacts."""
    conn = get_db(username)
    rows = conn.execute(
        "SELECT * FROM contacts WHERE is_blocked = 0 ORDER BY username"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_contact_keys(username, contact_username, identity_pub, signing_pub, fingerprint):
    """Update a contact's public keys (e.g., after key change detection)."""
    conn = get_db(username)
    conn.execute(
        """UPDATE contacts 
        SET identity_public_key = ?, signing_public_key = ?, 
            fingerprint = ?, is_verified = 0
        WHERE username = ?""",
        (identity_pub, signing_pub, fingerprint, contact_username)
    )
    conn.commit()
    conn.close()


def set_contact_verified(username, contact_username, verified=True):
    """Mark a contact as verified (user confirmed fingerprint out-of-band)."""
    conn = get_db(username)
    conn.execute(
        "UPDATE contacts SET is_verified = ? WHERE username = ?",
        (1 if verified else 0, contact_username)
    )
    conn.commit()
    conn.close()


def remove_contact(username, contact_username):
    """Remove a contact and their session/messages."""
    conn = get_db(username)
    conn.execute("DELETE FROM seen_counters WHERE contact_username = ?", (contact_username,))
    conn.execute("DELETE FROM messages WHERE contact_username = ?", (contact_username,))
    conn.execute("DELETE FROM sessions WHERE contact_username = ?", (contact_username,))
    conn.execute("DELETE FROM contacts WHERE username = ?", (contact_username,))
    conn.commit()
    conn.close()


# ============================================================
# E2EE session state
# ============================================================

def store_session(username, contact_username, shared_secret,
                  sending_chain_key, receiving_chain_key,
                  ephemeral_public=None, is_established=False):
    """Store or update the E2EE session state for a contact."""
    conn = get_db(username)
    try:
        conn.execute(
            """INSERT INTO sessions 
            (contact_username, shared_secret, sending_chain_key, receiving_chain_key,
             ephemeral_public_key, is_established)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (contact_username, shared_secret, sending_chain_key, receiving_chain_key,
             ephemeral_public, 1 if is_established else 0)
        )
    except sqlite3.IntegrityError:
        conn.execute(
            """UPDATE sessions 
            SET shared_secret = ?, sending_chain_key = ?, receiving_chain_key = ?,
                ephemeral_public_key = ?, is_established = ?,
                send_counter = 0, recv_counter = 0
            WHERE contact_username = ?""",
            (shared_secret, sending_chain_key, receiving_chain_key,
             ephemeral_public, 1 if is_established else 0, contact_username)
        )
    conn.commit()
    conn.close()


def get_session(username, contact_username):
    """Get the session state for a contact."""
    conn = get_db(username)
    row = conn.execute(
        "SELECT * FROM sessions WHERE contact_username = ?",
        (contact_username,)
    ).fetchone()
    conn.close()
    if row is None:
        return None
    result = dict(row)
    # Convert memoryview to bytes
    for key in ["shared_secret", "sending_chain_key", "receiving_chain_key", "ephemeral_public_key"]:
        if result.get(key):
            result[key] = bytes(result[key])
    return result


def increment_send_counter(username, contact_username):
    """Increment the send counter and return the current value."""
    conn = get_db(username)
    row = conn.execute(
        "SELECT send_counter FROM sessions WHERE contact_username = ?",
        (contact_username,)
    ).fetchone()

    if row is None:
        conn.close()
        return 0

    current = row["send_counter"]
    conn.execute(
        "UPDATE sessions SET send_counter = ? WHERE contact_username = ?",
        (current + 1, contact_username)
    )
    conn.commit()
    conn.close()
    return current


def mark_session_established(username, contact_username):
    """Mark a session as fully established (both sides have keys)."""
    conn = get_db(username)
    conn.execute(
        "UPDATE sessions SET is_established = 1 WHERE contact_username = ?",
        (contact_username,)
    )
    conn.commit()
    conn.close()


# ============================================================
# Message storage
# ============================================================

def store_message(username, contact_username, sender, content,
                  message_counter, is_incoming, ttl=None, status="sent"):
    """
    Store a message in the local database.
    
    Args:
        username: our username (DB file)
        contact_username: the conversation partner
        sender: who sent the message
        content: decrypted plaintext
        message_counter: counter for this message
        is_incoming: True if we received it, False if we sent it
        ttl: time-to-live in seconds (None = no expiry)
        status: 'sent' or 'delivered'
    """
    expires_at = None
    if ttl is not None and ttl > 0:
        expires_at = (datetime.datetime.utcnow() + 
                      datetime.timedelta(seconds=ttl)).isoformat()

    conn = get_db(username)
    conn.execute(
        """INSERT INTO messages 
        (contact_username, sender, content, message_counter, is_incoming, ttl, expires_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (contact_username, sender, content, message_counter,
         1 if is_incoming else 0, ttl, expires_at, status)
    )
    conn.commit()
    conn.close()


def get_messages(username, contact_username, limit=50, offset=0):
    """
    Get messages for a conversation with pagination (R25).
    Returns messages ordered by time, newest last.
    """
    conn = get_db(username)

    # First, delete expired self-destruct messages (R11)
    conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?",
        (datetime.datetime.utcnow().isoformat(),)
    )
    conn.commit()

    rows = conn.execute(
        """SELECT * FROM messages 
        WHERE contact_username = ?
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?""",
        (contact_username, limit, offset)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_message_status(username, contact_username, message_counter, status):
    """Update a message's delivery status."""
    conn = get_db(username)
    conn.execute(
        """UPDATE messages SET status = ? 
        WHERE contact_username = ? AND message_counter = ? AND is_incoming = 0""",
        (status, contact_username, message_counter)
    )
    conn.commit()
    conn.close()


def get_conversations(username):
    """
    Get the conversation list with last message time and unread count (R23, R24).
    Returns conversations ordered by most recent activity.
    """
    conn = get_db(username)

    # Clean up expired messages first
    conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?",
        (datetime.datetime.utcnow().isoformat(),)
    )
    conn.commit()

    rows = conn.execute(
        """SELECT 
            c.username,
            c.is_verified,
            MAX(m.timestamp) as last_message_time,
            COUNT(CASE WHEN m.is_incoming = 1 AND m.status = 'sent' THEN 1 END) as unread_count,
            (SELECT content FROM messages 
             WHERE contact_username = c.username 
             ORDER BY timestamp DESC LIMIT 1) as last_message
        FROM contacts c
        LEFT JOIN messages m ON c.username = m.contact_username
        WHERE c.is_blocked = 0
        GROUP BY c.username
        HAVING last_message_time IS NOT NULL
        ORDER BY last_message_time DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup_expired_messages(username):
    """Delete expired self-destruct messages from local storage (R11)."""
    conn = get_db(username)
    deleted = conn.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < ?",
        (datetime.datetime.utcnow().isoformat(),)
    ).rowcount
    conn.commit()
    conn.close()
    return deleted


# ============================================================
# Replay protection (R9, R22)
# ============================================================

def is_counter_seen(username, contact_username, message_counter):
    """
    Check if we've already processed a message with this counter.
    This prevents replay attacks and duplicate messages.
    """
    conn = get_db(username)
    row = conn.execute(
        "SELECT 1 FROM seen_counters WHERE contact_username = ? AND message_counter = ?",
        (contact_username, message_counter)
    ).fetchone()
    conn.close()
    return row is not None


def mark_counter_seen(username, contact_username, message_counter):
    """Record that we've processed a message with this counter."""
    conn = get_db(username)
    try:
        conn.execute(
            "INSERT INTO seen_counters (contact_username, message_counter) VALUES (?, ?)",
            (contact_username, message_counter)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # already recorded
    conn.close()
