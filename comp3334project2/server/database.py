"""
database.py - Server-side database operations for the Secure IM application.

This module handles all SQLite database interactions for the server,
including user management, friend requests, session tokens, and offline
message storage. The database is local (SQLite) and stores only public
keys and ciphertext -- never plaintext messages or private keys.

Security notes:
- Passwords are hashed with Argon2id before storage
- The server is honest-but-curious: it follows the protocol but we
  design as if it might inspect any data it can access
- Message contents are always encrypted (E2EE) before reaching the server
"""

import sqlite3
import os
import time
import secrets
import datetime

# Argon2 for secure password hashing (memory-hard, resistant to GPU attacks)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


# ============================================================
# Database initialization
# ============================================================

# Path to the server database file
DB_PATH = os.path.join(os.path.dirname(__file__), "server.db")

# Initialize the Argon2id password hasher with reasonable parameters
# time_cost=3: number of iterations
# memory_cost=65536: 64 MB memory usage (makes GPU attacks expensive)
# parallelism=4: number of threads
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)


def get_db():
    """Get a database connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows accessing columns by name
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")   # enforce foreign key constraints
    return conn


def init_db():
    """Initialize the database using the SQL schema file."""
    schema_path = os.path.join(os.path.dirname(__file__), "..", "setup_database.sql")
    conn = get_db()
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
    conn.close()
    print("[DB] Database initialized successfully.")


# ============================================================
# User management
# ============================================================

def create_user(username, password, otp_secret):
    """
    Register a new user with hashed password and OTP secret.
    Returns the new user's ID, or None if username already exists.
    """
    # Hash the password using Argon2id (salt is auto-generated and embedded)
    password_hash = password_hasher.hash(password)

    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, otp_secret) VALUES (?, ?, ?)",
            (username, password_hash, otp_secret)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        # Username already taken
        return None
    finally:
        conn.close()


def verify_password(username, password):
    """
    Verify a user's password against the stored Argon2id hash.
    Returns the user dict if valid, None otherwise.
    """
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,)
    ).fetchone()
    conn.close()

    if user is None:
        return None

    try:
        # Argon2 verify checks the password against the stored hash
        password_hasher.verify(user["password_hash"], password)
        return dict(user)
    except VerifyMismatchError:
        return None


def get_user_by_username(username):
    """Look up a user by their username."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Look up a user by their ID."""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND is_active = 1",
        (user_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


# ============================================================
# Public key management
# ============================================================

def store_user_keys(user_id, identity_public_key, signing_public_key):
    """
    Store a user's public keys for E2EE key exchange.
    If keys already exist for this user, update them (key rotation).
    """
    conn = get_db()
    # Use INSERT OR REPLACE to handle key updates
    conn.execute(
        """INSERT OR REPLACE INTO user_keys 
        (user_id, identity_public_key, signing_public_key) 
        VALUES (?, ?, ?)""",
        (user_id, identity_public_key, signing_public_key)
    )
    conn.commit()
    conn.close()


def get_user_keys(username):
    """
    Retrieve a user's public keys by username.
    Returns dict with identity_public_key and signing_public_key, or None.
    """
    conn = get_db()
    result = conn.execute(
        """SELECT uk.identity_public_key, uk.signing_public_key 
        FROM user_keys uk 
        JOIN users u ON uk.user_id = u.id 
        WHERE u.username = ?""",
        (username,)
    ).fetchone()
    conn.close()
    return dict(result) if result else None


# ============================================================
# Session / token management
# ============================================================

# Sessions expire after 24 hours
SESSION_DURATION_HOURS = 24


def create_session(user_id):
    """
    Create a new session token for an authenticated user.
    Returns the token string.
    """
    # Generate a cryptographically secure random token (32 bytes = 64 hex chars)
    token = secrets.token_hex(32)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=SESSION_DURATION_HOURS)

    conn = get_db()
    conn.execute(
        "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user_id, token, expires_at)
    )
    conn.commit()
    conn.close()
    return token


def validate_session(token):
    """
    Check if a session token is valid (exists, not expired, not revoked).
    Returns the user dict if valid, None otherwise.
    """
    conn = get_db()
    session = conn.execute(
        """SELECT s.user_id, u.username FROM sessions s 
        JOIN users u ON s.user_id = u.id 
        WHERE s.token = ? AND s.is_valid = 1 AND s.expires_at > ?""",
        (token, datetime.datetime.now(datetime.timezone.utc))
    ).fetchone()
    conn.close()
    return dict(session) if session else None


def invalidate_session(token):
    """Invalidate a session token (used on logout)."""
    conn = get_db()
    conn.execute(
        "UPDATE sessions SET is_valid = 0 WHERE token = ?",
        (token,)
    )
    conn.commit()
    conn.close()


def invalidate_all_sessions(user_id):
    """Invalidate all sessions for a user (e.g., on password change)."""
    conn = get_db()
    conn.execute(
        "UPDATE sessions SET is_valid = 0 WHERE user_id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


# ============================================================
# Friend request management
# ============================================================

def create_friend_request(sender_id, receiver_id):
    """
    Send a friend request. Returns True if successful, False if blocked
    or duplicate request exists.
    """
    conn = get_db()

    # Check if the receiver has blocked the sender
    blocked = conn.execute(
        "SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (receiver_id, sender_id)
    ).fetchone()
    if blocked:
        conn.close()
        return False, "You are blocked by this user."

    # Check if they're already friends
    existing_friend = conn.execute(
        "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
        (sender_id, receiver_id)
    ).fetchone()
    if existing_friend:
        conn.close()
        return False, "Already friends."

    # Check for existing pending request in either direction
    existing = conn.execute(
        """SELECT 1 FROM friend_requests 
        WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) 
        AND status = 'pending'""",
        (sender_id, receiver_id, receiver_id, sender_id)
    ).fetchone()
    if existing:
        conn.close()
        return False, "A pending friend request already exists."

    conn.execute(
        "INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)",
        (sender_id, receiver_id)
    )
    conn.commit()
    conn.close()
    return True, "Friend request sent."


def get_pending_requests(user_id):
    """Get all pending friend requests received by this user."""
    conn = get_db()
    requests = conn.execute(
        """SELECT fr.id, fr.sender_id, u.username as sender_username, fr.created_at
        FROM friend_requests fr 
        JOIN users u ON fr.sender_id = u.id 
        WHERE fr.receiver_id = ? AND fr.status = 'pending'""",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in requests]


def get_sent_requests(user_id):
    """Get all pending friend requests sent by this user."""
    conn = get_db()
    requests = conn.execute(
        """SELECT fr.id, fr.receiver_id, u.username as receiver_username, fr.created_at
        FROM friend_requests fr 
        JOIN users u ON fr.receiver_id = u.id 
        WHERE fr.sender_id = ? AND fr.status = 'pending'""",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in requests]


def accept_friend_request(request_id, receiver_id):
    """
    Accept a friend request. Creates bidirectional friend entries.
    Returns (success, message).
    """
    conn = get_db()
    request = conn.execute(
        "SELECT * FROM friend_requests WHERE id = ? AND receiver_id = ? AND status = 'pending'",
        (request_id, receiver_id)
    ).fetchone()

    if not request:
        conn.close()
        return False, "Friend request not found."

    sender_id = request["sender_id"]

    # Update request status
    conn.execute(
        "UPDATE friend_requests SET status = 'accepted' WHERE id = ?",
        (request_id,)
    )

    # Create bidirectional friendship (both directions for easy lookup)
    try:
        conn.execute(
            "INSERT INTO friends (user_id, friend_id) VALUES (?, ?)",
            (sender_id, receiver_id)
        )
        conn.execute(
            "INSERT INTO friends (user_id, friend_id) VALUES (?, ?)",
            (receiver_id, sender_id)
        )
    except sqlite3.IntegrityError:
        pass  # already friends somehow

    conn.commit()
    conn.close()
    return True, "Friend request accepted."


def decline_friend_request(request_id, receiver_id):
    """Decline a friend request."""
    conn = get_db()
    result = conn.execute(
        "UPDATE friend_requests SET status = 'declined' WHERE id = ? AND receiver_id = ? AND status = 'pending'",
        (request_id, receiver_id)
    )
    conn.commit()
    affected = result.rowcount
    conn.close()
    return affected > 0


def cancel_friend_request(request_id, sender_id):
    """Cancel a sent friend request."""
    conn = get_db()
    result = conn.execute(
        "UPDATE friend_requests SET status = 'cancelled' WHERE id = ? AND sender_id = ? AND status = 'pending'",
        (request_id, sender_id)
    )
    conn.commit()
    affected = result.rowcount
    conn.close()
    return affected > 0


def get_friends(user_id):
    """Get all friends for a user."""
    conn = get_db()
    friends = conn.execute(
        """SELECT u.id, u.username 
        FROM friends f 
        JOIN users u ON f.friend_id = u.id 
        WHERE f.user_id = ?""",
        (user_id,)
    ).fetchall()
    conn.close()
    return [dict(f) for f in friends]


def remove_friend(user_id, friend_id):
    """Remove a friendship (both directions)."""
    conn = get_db()
    conn.execute(
        "DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)",
        (user_id, friend_id, friend_id, user_id)
    )
    conn.commit()
    conn.close()


def are_friends(user_id, friend_id):
    """Check if two users are friends."""
    conn = get_db()
    result = conn.execute(
        "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
        (user_id, friend_id)
    ).fetchone()
    conn.close()
    return result is not None


# ============================================================
# Block management
# ============================================================

def block_user(blocker_id, blocked_id):
    """Block a user. Also removes friendship if it exists."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)",
            (blocker_id, blocked_id)
        )
    except sqlite3.IntegrityError:
        pass  # already blocked

    # Remove friendship in both directions
    conn.execute(
        "DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)",
        (blocker_id, blocked_id, blocked_id, blocker_id)
    )

    # Cancel any pending friend requests
    conn.execute(
        """UPDATE friend_requests SET status = 'cancelled' 
        WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) 
        AND status = 'pending'""",
        (blocker_id, blocked_id, blocked_id, blocker_id)
    )
    conn.commit()
    conn.close()


def is_blocked(blocker_id, blocked_id):
    """Check if blocker has blocked the blocked user."""
    conn = get_db()
    result = conn.execute(
        "SELECT 1 FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (blocker_id, blocked_id)
    ).fetchone()
    conn.close()
    return result is not None


def unblock_user(blocker_id, blocked_id):
    """Unblock a user."""
    conn = get_db()
    conn.execute(
        "DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?",
        (blocker_id, blocked_id)
    )
    conn.commit()
    conn.close()


# ============================================================
# Offline message queue
# ============================================================

def store_offline_message(sender_id, receiver_id, ciphertext, nonce,
                          ephemeral_key, message_counter, ttl, associated_data):
    """
    Store an encrypted message for an offline user.
    The server only stores ciphertext and metadata -- it cannot decrypt.
    """
    expires_at = None
    if ttl is not None:
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl)

    conn = get_db()
    conn.execute(
        """INSERT INTO offline_messages 
        (sender_id, receiver_id, ciphertext, nonce, ephemeral_key, 
         message_counter, ttl, associated_data, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (sender_id, receiver_id, ciphertext, nonce, ephemeral_key,
         message_counter, ttl, associated_data, expires_at)
    )
    conn.commit()
    conn.close()


def get_offline_messages(receiver_id):
    """
    Retrieve all pending offline messages for a user.
    Also deletes expired messages before returning.
    """
    conn = get_db()

    # First, clean up expired messages (best-effort server-side deletion for R12)
    conn.execute(
        "DELETE FROM offline_messages WHERE expires_at IS NOT NULL AND expires_at < ?",
        (datetime.datetime.now(datetime.timezone.utc),)
    )
    conn.commit()

    # Fetch remaining undelivered messages
    messages = conn.execute(
        """SELECT om.*, u.username as sender_username 
        FROM offline_messages om 
        JOIN users u ON om.sender_id = u.id 
        WHERE om.receiver_id = ? AND om.delivered = 0
        ORDER BY om.created_at ASC""",
        (receiver_id,)
    ).fetchall()
    conn.close()
    return [dict(m) for m in messages]


def mark_offline_delivered(message_ids):
    """Mark offline messages as delivered."""
    if not message_ids:
        return
    conn = get_db()
    placeholders = ",".join("?" * len(message_ids))
    conn.execute(
        f"UPDATE offline_messages SET delivered = 1 WHERE id IN ({placeholders})",
        message_ids
    )
    conn.commit()
    conn.close()


def cleanup_expired_messages():
    """Delete expired offline messages (called periodically by the server)."""
    conn = get_db()
    deleted = conn.execute(
        "DELETE FROM offline_messages WHERE expires_at IS NOT NULL AND expires_at < ?",
        (datetime.datetime.now(datetime.timezone.utc),)
    ).rowcount
    # Also delete delivered messages older than 24 hours
    conn.execute(
        "DELETE FROM offline_messages WHERE delivered = 1 AND created_at < ?",
        (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24),)
    )
    conn.commit()
    conn.close()
    return deleted


# ============================================================
# Rate limiting
# ============================================================

# Rate limit configuration: (max_attempts, window_seconds)
RATE_LIMITS = {
    "login": (999, 300),           # Relaxed for testing: 999 attempts per 5 minutes
    "register": (999, 3600),       # Relaxed for testing: 999 registrations per hour
    "friend_request": (999, 3600) # Relaxed for testing: 999 friend requests per hour
}


def check_rate_limit(identifier, action):
    """
    Check if an action is rate-limited.
    Returns True if the action is allowed, False if rate-limited.
    """
    if action not in RATE_LIMITS:
        return True

    max_attempts, window = RATE_LIMITS[action]
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=window)

    conn = get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM rate_limits WHERE identifier = ? AND action = ? AND attempt_time > ?",
        (identifier, action, cutoff)
    ).fetchone()[0]
    conn.close()

    return count < max_attempts


def record_rate_limit(identifier, action):
    """Record an action attempt for rate limiting."""
    conn = get_db()
    conn.execute(
        "INSERT INTO rate_limits (identifier, action) VALUES (?, ?)",
        (identifier, action)
    )
    # Clean up old rate limit records (older than 1 day)
    conn.execute(
        "DELETE FROM rate_limits WHERE attempt_time < ?",
        (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),)
    )
    conn.commit()
    conn.close()
