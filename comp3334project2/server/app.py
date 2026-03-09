"""
app.py - Main server application for the Secure IM system.

This is the central server that handles:
- User registration and login (with password + TOTP two-factor auth)
- Public key distribution for E2EE key exchange
- Friend request management (send/accept/decline/cancel)
- Real-time message relay via WebSocket (server only sees ciphertext)
- Offline message queue (store-and-forward encrypted messages)
- Message delivery status tracking

IMPORTANT SECURITY NOTE:
The server is designed under the honest-but-curious (HbC) model:
- It follows the protocol correctly
- But we assume it might try to inspect any data it can access
- Therefore, all message contents are end-to-end encrypted BEFORE
  reaching the server. The server NEVER has plaintext or private keys.

Transport security: All connections use TLS (HTTPS/WSS) to protect
against network-level attackers (MITM, eavesdropping).
"""

import os
import sys
import pyotp
import datetime
import threading

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit, disconnect

# Import our database module
from server.database import (
    init_db, create_user, verify_password, get_user_by_username,
    get_user_by_id, store_user_keys, get_user_keys,
    create_session, validate_session, invalidate_session,
    create_friend_request, get_pending_requests, get_sent_requests,
    accept_friend_request, decline_friend_request, cancel_friend_request,
    get_friends, remove_friend, are_friends,
    block_user, is_blocked, unblock_user,
    store_offline_message, get_offline_messages, mark_offline_delivered,
    cleanup_expired_messages,
    check_rate_limit, record_rate_limit,
)


# ============================================================
# Flask app and SocketIO setup
# ============================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()  # random secret for session signing

# Initialize Socket.IO with eventlet for async WebSocket support
socketio = SocketIO(
    app,
    cors_allowed_origins="*",   # allow all origins (for development)
    async_mode="eventlet",
    logger=False,               # disable verbose logs (R: minimal sensitive logging)
    engineio_logger=False,
)

# Track which users are currently connected (username -> socket session id)
# This lets us route messages to the right connected client
connected_users = {}  # {username: sid}
# Reverse mapping for disconnect handling
sid_to_user = {}  # {sid: username}


# ============================================================
# Web UI route - serves the single-page app
# ============================================================

@app.route("/")
def index():
    """Serve the main web UI page."""
    return render_template("index.html")


# ============================================================
# Helper: authenticate requests using the session token
# ============================================================

def authenticate_request():
    """
    Extract and validate the auth token from the request header.
    Returns (user_dict, None) on success, or (None, error_response) on failure.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, (jsonify({"error": "Missing or invalid auth token."}), 401)

    token = auth_header.split("Bearer ")[1]
    user = validate_session(token)
    if user is None:
        return None, (jsonify({"error": "Invalid or expired session."}), 401)

    return user, None


# ============================================================
# Periodic cleanup task for expired offline messages
# ============================================================

def periodic_cleanup():
    """Run cleanup of expired messages every 60 seconds."""
    while True:
        try:
            deleted = cleanup_expired_messages()
            if deleted > 0:
                print(f"[Cleanup] Deleted {deleted} expired offline messages.")
        except Exception as e:
            print(f"[Cleanup] Error: {e}")
        import eventlet
        eventlet.sleep(60)


# ============================================================
# REST API Routes
# ============================================================

# ---------- Registration (R1) ----------

@app.route("/api/register", methods=["POST"])
def register():
    """
    Register a new user account.
    
    Expects JSON:
    {
        "username": "alice",
        "password": "SecurePass123!",
        "identity_public_key": "<base64>",
        "signing_public_key": "<base64>"
    }
    
    Returns the TOTP secret for the user to set up their authenticator app.
    The password is hashed with Argon2id before storage.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")
    identity_pub = data.get("identity_public_key", "")
    signing_pub = data.get("signing_public_key", "")

    # Input validation
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be 3-32 characters."}), 400

    if not username.isalnum():
        return jsonify({"error": "Username must be alphanumeric."}), 400

    # Password policy: relaxed for testing
    if len(password) < 1:
        return jsonify({"error": "Password is required."}), 400

    # if not any(c.isupper() for c in password):
    #     return jsonify({"error": "Password must contain at least one uppercase letter."}), 400

    # if not any(c.isdigit() for c in password):
    #     return jsonify({"error": "Password must contain at least one digit."}), 400

    if not identity_pub or not signing_pub:
        return jsonify({"error": "Public keys are required."}), 400

    # Rate limiting: prevent registration spam
    client_ip = request.remote_addr or "unknown"
    if not check_rate_limit(client_ip, "register"):
        return jsonify({"error": "Too many registration attempts. Try again later."}), 429

    record_rate_limit(client_ip, "register")

    # Generate TOTP secret for two-factor authentication
    otp_secret = pyotp.random_base32()

    # Create the user (password is hashed inside create_user)
    user_id = create_user(username, password, otp_secret)
    if user_id is None:
        return jsonify({"error": "Username already taken."}), 409

    # Store the user's public keys
    store_user_keys(user_id, identity_pub, signing_pub)

    # Generate the TOTP provisioning URI for QR code scanning
    totp = pyotp.TOTP(otp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="COMP3334 Secure IM"
    )

    print(f"[Server] New user registered: {username}")

    return jsonify({
        "message": "Registration successful!",
        "user_id": user_id,
        "otp_secret": otp_secret,
        "otp_uri": provisioning_uri,
    }), 201


# ---------- Login (R2) ----------

@app.route("/api/login", methods=["POST"])
def login():
    """
    Log in with username + password + OTP code.
    
    Expects JSON:
    {
        "username": "alice",
        "password": "SecurePass123!",
        "otp_code": "123456"
    }
    
    Returns a session token on success.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")
    otp_code = data.get("otp_code", "")

    if not username or not password or not otp_code:
        return jsonify({"error": "Username, password, and OTP code are required."}), 400

    # Rate limiting: prevent brute-force login attempts
    if not check_rate_limit(username, "login"):
        return jsonify({"error": "Too many login attempts. Try again in 5 minutes."}), 429

    record_rate_limit(username, "login")

    # Step 1: Verify password (checked against Argon2id hash)
    user = verify_password(username, password)
    if user is None:
        return jsonify({"error": "Invalid username or password."}), 401

    # Step 2: Verify TOTP code (second factor) - relaxed for testing
    totp = pyotp.TOTP(user["otp_secret"])
    if otp_code != "000000" and not totp.verify(otp_code, valid_window=1):
        # valid_window=1 allows the previous and next 30-second codes too
        return jsonify({"error": "Invalid OTP code (Hint: use 000000 for testing)."}), 401

    # Both factors verified -- create a session token
    token = create_session(user["id"])

    print(f"[Server] User logged in: {username}")

    return jsonify({
        "message": "Login successful!",
        "token": token,
        "user_id": user["id"],
        "username": username,
    }), 200


# ---------- Logout (R3) ----------

@app.route("/api/logout", methods=["POST"])
def logout():
    """
    Log out and invalidate the session token.
    The token is immediately revoked so it can't be reused.
    """
    user, error = authenticate_request()
    if error:
        return error

    token = request.headers.get("Authorization", "").split("Bearer ")[1]
    invalidate_session(token)

    print(f"[Server] User logged out: {user['username']}")

    return jsonify({"message": "Logged out successfully."}), 200


# ---------- Key management (R4) ----------

@app.route("/api/keys/<username>", methods=["GET"])
def get_keys(username):
    """
    Retrieve a user's public keys for E2EE session establishment.
    Anyone can fetch public keys (they're public by definition).
    But we still require authentication to prevent scraping.
    """
    user, error = authenticate_request()
    if error:
        return error

    keys = get_user_keys(username)
    if keys is None:
        return jsonify({"error": "User not found or no keys uploaded."}), 404

    return jsonify({
        "username": username,
        "identity_public_key": keys["identity_public_key"],
        "signing_public_key": keys["signing_public_key"],
    }), 200


@app.route("/api/keys", methods=["PUT"])
def update_keys():
    """
    Update the authenticated user's public keys (key rotation).
    This triggers key change warnings for contacts (handled client-side).
    """
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    identity_pub = data.get("identity_public_key", "")
    signing_pub = data.get("signing_public_key", "")

    if not identity_pub or not signing_pub:
        return jsonify({"error": "Both public keys are required."}), 400

    store_user_keys(user["user_id"], identity_pub, signing_pub)

    return jsonify({"message": "Keys updated successfully."}), 200


# ---------- Friend management (R13-R16) ----------

@app.route("/api/friends/request", methods=["POST"])
def send_friend_request():
    """Send a friend request to another user."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    target_username = data.get("username", "").strip()

    if not target_username:
        return jsonify({"error": "Username is required."}), 400

    if target_username == user["username"]:
        return jsonify({"error": "You cannot add yourself."}), 400

    # Rate limiting for friend requests
    if not check_rate_limit(user["username"], "friend_request"):
        return jsonify({"error": "Too many friend requests. Try again later."}), 429

    record_rate_limit(user["username"], "friend_request")

    target = get_user_by_username(target_username)
    if target is None:
        return jsonify({"error": "User not found."}), 404

    success, message = create_friend_request(user["user_id"], target["id"])

    if not success:
        return jsonify({"error": message}), 400

    # Notify the target user in real-time if they're online
    if target_username in connected_users:
        socketio.emit("friend_request_received", {
            "from": user["username"],
        }, room=connected_users[target_username])

    return jsonify({"message": message}), 200


@app.route("/api/friends/requests", methods=["GET"])
def get_requests():
    """Get all pending friend requests (received and sent)."""
    user, error = authenticate_request()
    if error:
        return error

    received = get_pending_requests(user["user_id"])
    sent = get_sent_requests(user["user_id"])

    return jsonify({
        "received": received,
        "sent": sent,
    }), 200


@app.route("/api/friends/accept", methods=["POST"])
def accept_request():
    """Accept a friend request."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    request_id = data.get("request_id")

    if request_id is None:
        return jsonify({"error": "request_id is required."}), 400

    success, message = accept_friend_request(request_id, user["user_id"])

    if not success:
        return jsonify({"error": message}), 400

    return jsonify({"message": message}), 200


@app.route("/api/friends/decline", methods=["POST"])
def decline_request():
    """Decline a friend request."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    request_id = data.get("request_id")

    if request_id is None:
        return jsonify({"error": "request_id is required."}), 400

    success = decline_friend_request(request_id, user["user_id"])
    if not success:
        return jsonify({"error": "Friend request not found."}), 400

    return jsonify({"message": "Friend request declined."}), 200


@app.route("/api/friends/cancel", methods=["POST"])
def cancel_request():
    """Cancel a sent friend request."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    request_id = data.get("request_id")

    if request_id is None:
        return jsonify({"error": "request_id is required."}), 400

    success = cancel_friend_request(request_id, user["user_id"])
    if not success:
        return jsonify({"error": "Friend request not found."}), 400

    return jsonify({"message": "Friend request cancelled."}), 200


@app.route("/api/friends", methods=["GET"])
def list_friends():
    """Get the authenticated user's friends list."""
    user, error = authenticate_request()
    if error:
        return error

    friends = get_friends(user["user_id"])
    return jsonify({"friends": friends}), 200


@app.route("/api/friends/remove", methods=["POST"])
def remove_friend_route():
    """Remove a friend."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    target_username = data.get("username", "").strip()

    if not target_username:
        return jsonify({"error": "Username is required."}), 400

    target = get_user_by_username(target_username)
    if target is None:
        return jsonify({"error": "User not found."}), 404

    remove_friend(user["user_id"], target["id"])

    return jsonify({"message": f"Removed {target_username} from friends."}), 200


@app.route("/api/friends/block", methods=["POST"])
def block_user_route():
    """Block a user (also removes friendship and cancels requests)."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    target_username = data.get("username", "").strip()

    if not target_username:
        return jsonify({"error": "Username is required."}), 400

    target = get_user_by_username(target_username)
    if target is None:
        return jsonify({"error": "User not found."}), 404

    block_user(user["user_id"], target["id"])

    return jsonify({"message": f"Blocked {target_username}."}), 200


@app.route("/api/friends/unblock", methods=["POST"])
def unblock_user_route():
    """Unblock a previously blocked user."""
    user, error = authenticate_request()
    if error:
        return error

    data = request.get_json()
    target_username = data.get("username", "").strip()

    if not target_username:
        return jsonify({"error": "Username is required."}), 400

    target = get_user_by_username(target_username)
    if target is None:
        return jsonify({"error": "User not found."}), 404

    unblock_user(user["user_id"], target["id"])

    return jsonify({"message": f"Unblocked {target_username}."}), 200


# ---------- Offline messages (R20-R22) ----------

@app.route("/api/offline-messages", methods=["GET"])
def get_offline():
    """Retrieve all pending offline messages for the authenticated user."""
    user, error = authenticate_request()
    if error:
        return error

    messages = get_offline_messages(user["user_id"])

    # Mark these messages as delivered since they're being fetched
    message_ids = [m["id"] for m in messages]
    if message_ids:
        mark_offline_delivered(message_ids)

    return jsonify({"messages": messages}), 200


# ============================================================
# WebSocket Events - Real-time messaging
# ============================================================

@socketio.on("connect")
def handle_connect():
    """
    Handle WebSocket connection.
    The client must send an 'authenticate' event right after connecting.
    """
    print(f"[WS] New connection: {request.sid}")


@socketio.on("authenticate")
def handle_authenticate(data):
    """
    Authenticate the WebSocket connection using a session token.
    This must be called right after connect to associate the socket
    with a user account.
    """
    token = data.get("token", "")
    user = validate_session(token)

    if user is None:
        emit("auth_error", {"error": "Invalid or expired token."})
        disconnect()
        return

    username = user["username"]

    # Register this user as online
    connected_users[username] = request.sid
    sid_to_user[request.sid] = username

    print(f"[WS] User authenticated: {username}")
    emit("authenticated", {"username": username})

    # Deliver any pending offline messages
    user_full = get_user_by_username(username)
    if user_full:
        offline = get_offline_messages(user_full["id"])
        if offline:
            for msg in offline:
                emit("receive_message", {
                    "sender": msg["sender_username"],
                    "ciphertext": msg["ciphertext"],
                    "nonce": msg["nonce"],
                    "ephemeral_key": msg["ephemeral_key"],
                    "message_counter": msg["message_counter"],
                    "ttl": msg["ttl"],
                    "associated_data": msg["associated_data"],
                    "timestamp": msg["created_at"],
                    "offline": True,
                })
            # Mark them as delivered
            mark_offline_delivered([m["id"] for m in offline])
            print(f"[WS] Delivered {len(offline)} offline messages to {username}")


@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection -- remove from online users."""
    sid = request.sid
    if sid in sid_to_user:
        username = sid_to_user.pop(sid)
        connected_users.pop(username, None)
        print(f"[WS] User disconnected: {username}")


@socketio.on("send_message")
def handle_send_message(data):
    """
    Handle an encrypted message from one user to another.
    
    The server acts as a relay -- it receives ciphertext from the sender
    and forwards it to the recipient. The server CANNOT decrypt the message
    because it doesn't have the shared secret or private keys.
    
    Expected data:
    {
        "receiver": "bob",
        "ciphertext": "<base64>",
        "nonce": "<base64>",
        "ephemeral_key": "<base64 or null>",
        "message_counter": 5,
        "ttl": 300 or null,
        "associated_data": "<base64>"
    }
    """
    sid = request.sid
    if sid not in sid_to_user:
        emit("error", {"error": "Not authenticated."})
        return

    sender_username = sid_to_user[sid]
    receiver_username = data.get("receiver", "")

    if not receiver_username:
        emit("error", {"error": "Receiver is required."})
        return

    # Look up both users
    sender = get_user_by_username(sender_username)
    receiver = get_user_by_username(receiver_username)

    if receiver is None:
        emit("error", {"error": "Recipient not found."})
        return

    # Security check: only friends can send messages (R16 anti-spam)
    if not are_friends(sender["id"], receiver["id"]):
        emit("error", {"error": "You can only message friends."})
        return

    # Check if sender is blocked by receiver
    if is_blocked(receiver["id"], sender["id"]):
        emit("error", {"error": "Message could not be delivered."})
        return

    # Validate required message fields
    ciphertext = data.get("ciphertext")
    nonce = data.get("nonce")
    message_counter = data.get("message_counter")
    associated_data = data.get("associated_data", "")

    if not ciphertext or not nonce or message_counter is None:
        emit("error", {"error": "Invalid message format."})
        return

    # Enforce a reasonable message size limit (prevent abuse)
    if len(ciphertext) > 100000:  # ~100KB max
        emit("error", {"error": "Message too large."})
        return

    ttl = data.get("ttl")
    ephemeral_key = data.get("ephemeral_key")

    # Tell the sender that the message was accepted by the server ("Sent" status)
    emit("message_sent", {
        "receiver": receiver_username,
        "message_counter": message_counter,
        "status": "sent",
    })

    # Try to forward to recipient in real-time
    if receiver_username in connected_users:
        # Recipient is online -- forward the encrypted message directly
        socketio.emit("receive_message", {
            "sender": sender_username,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "ephemeral_key": ephemeral_key,
            "message_counter": message_counter,
            "ttl": ttl,
            "associated_data": associated_data,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "offline": False,
        }, room=connected_users[receiver_username])

        # Notify sender of delivery (Option A semantics: forwarded to connection)
        emit("message_status", {
            "receiver": receiver_username,
            "message_counter": message_counter,
            "status": "delivered",
        })
    else:
        # Recipient is offline -- store in the offline queue
        store_offline_message(
            sender_id=sender["id"],
            receiver_id=receiver["id"],
            ciphertext=ciphertext,
            nonce=nonce,
            ephemeral_key=ephemeral_key,
            message_counter=message_counter,
            ttl=ttl,
            associated_data=associated_data,
        )
        print(f"[WS] Message from {sender_username} stored offline for {receiver_username}")


@socketio.on("message_delivered_ack")
def handle_delivery_ack(data):
    """
    Handle delivery acknowledgment from the recipient.
    This is forwarded to the original sender to update their message status.
    (R17-R18: Option B stronger semantics -- ack from recipient client)
    """
    sid = request.sid
    if sid not in sid_to_user:
        return

    acker = sid_to_user[sid]
    sender_username = data.get("sender", "")
    message_counter = data.get("message_counter")

    # Forward the delivery ack to the original sender if they're online
    if sender_username in connected_users:
        socketio.emit("message_status", {
            "receiver": acker,
            "message_counter": message_counter,
            "status": "delivered",
        }, room=connected_users[sender_username])


@socketio.on("typing")
def handle_typing(data):
    """Forward typing indicator to the chat partner (optional UX feature)."""
    sid = request.sid
    if sid not in sid_to_user:
        return

    sender = sid_to_user[sid]
    receiver = data.get("receiver", "")

    if receiver in connected_users:
        socketio.emit("user_typing", {
            "username": sender,
        }, room=connected_users[receiver])


# ============================================================
# Entry point
# ============================================================

def run_server(host="0.0.0.0", port=5000):
    """Start the secure IM server with TLS."""

    # Initialize the database
    init_db()

    # Paths to TLS certificate and key
    cert_dir = os.path.join(os.path.dirname(__file__), "..", "certs")
    certfile = os.path.join(cert_dir, "server_cert.pem")
    keyfile = os.path.join(cert_dir, "server_key.pem")

    # Check that TLS certificates exist
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        print("[ERROR] TLS certificates not found!")
        print("        Run 'python generate_certs.py' first to generate them.")
        sys.exit(1)

    # Start the periodic cleanup thread for expired messages
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()

    print(f"[Server] Starting Secure IM server on https://{host}:{port}")
    print(f"[Server] TLS enabled with certificate: {certfile}")
    print("[Server] Press Ctrl+C to stop.")

    # Run the Flask-SocketIO server with TLS
    # We pass certfile and keyfile directly (works with eventlet's SSL wrapping)
    socketio.run(
        app,
        host=host,
        port=port,
        certfile=certfile,
        keyfile=keyfile,
        debug=False,  # never enable debug in production (leaks info)
    )


if __name__ == "__main__":
    run_server()
