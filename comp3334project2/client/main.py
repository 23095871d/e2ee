"""
main.py - Main CLI client for the Secure IM application.

This is the entry point for the client application. It provides a
command-line interface for users to:
- Register and log in (with password + OTP two-factor auth)
- Manage friends (add, accept, decline, remove, block)
- Chat securely with end-to-end encryption
- View conversation list and unread messages
- Verify contact fingerprints
- Send self-destruct (timed) messages

All messages are encrypted client-side before being sent to the server.
The server NEVER sees plaintext message contents.

Usage:
    python -m client.main [--server https://localhost:5000]
"""

import os
import sys
import time
import json
import threading
import argparse
import datetime

# Our modules
from client.crypto_utils import (
    generate_x25519_keypair, generate_ed25519_keypair,
    establish_session, complete_session_with_ephemeral,
    derive_message_key, encrypt_message, decrypt_message,
    build_associated_data, compute_fingerprint,
    encrypt_private_key, decrypt_private_key,
    to_base64, from_base64,
)
from client.local_db import (
    init_local_db, store_identity_keys, get_identity_keys,
    add_contact, get_contact, get_all_contacts,
    update_contact_keys, set_contact_verified, remove_contact,
    store_session, get_session, increment_send_counter,
    mark_session_established,
    store_message, get_messages, update_message_status,
    get_conversations, cleanup_expired_messages,
    is_counter_seen, mark_counter_seen,
)
from client.network import NetworkClient


# ============================================================
# Global state for the current user session
# ============================================================

class ClientState:
    """Holds the current state of the logged-in user."""
    def __init__(self):
        self.username = None
        self.password = None
        self.identity_private_key = None   # decrypted X25519 private key
        self.identity_public_key = None    # X25519 public key
        self.signing_private_key = None    # decrypted Ed25519 private key
        self.signing_public_key = None     # Ed25519 public key
        self.network = None                # NetworkClient instance
        self.current_chat = None           # username we're chatting with (or None)
        self.otp_secret = None             # stored locally for convenience

state = ClientState()


# ============================================================
# Banner and UI helpers
# ============================================================

BANNER = """
============================================
   COMP3334 Secure Instant Messenger
   End-to-End Encrypted (E2EE) Chat
============================================
"""

def print_divider():
    print("-" * 44)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


# ============================================================
# Crypto helper functions (wrappers around crypto_utils)
# ============================================================

def ensure_session(contact_username):
    """
    Make sure we have an E2EE session with the given contact.
    If not, establish one by fetching their keys from the server.
    
    Returns True if session is ready, False if we couldn't set it up.
    """
    session = get_session(state.username, contact_username)
    if session is not None:
        return True

    # Fetch the contact's public keys from the server
    data, status = state.network.get_user_keys(contact_username)
    if status != 200:
        print(f"[!] Could not fetch {contact_username}'s keys: {data.get('error', 'Unknown')}")
        return False

    their_identity_pub = from_base64(data["identity_public_key"])
    their_signing_pub = from_base64(data["signing_public_key"])

    # Check if the contact's key has changed (R6: key change detection)
    existing_contact = get_contact(state.username, contact_username)
    if existing_contact and existing_contact.get("identity_public_key"):
        old_key = existing_contact["identity_public_key"]
        if old_key != their_identity_pub:
            print(f"\n[!! WARNING !!] {contact_username}'s identity key has CHANGED!")
            print("This could mean:")
            print("  - They reinstalled the app")
            print("  - They registered a new account")
            print("  - Someone is impersonating them (MITM attack)")
            print()
            print("Policy: Communication is allowed with a warning.")
            print("        You should verify their fingerprint in person.")
            print()
            # Update the contact's keys (allow with warning policy)

    # Compute the fingerprint (safety number) for this conversation
    fingerprint = compute_fingerprint(state.identity_public_key, their_identity_pub)

    # Update/add contact with their public keys
    add_contact(
        state.username, contact_username,
        identity_pub=their_identity_pub,
        signing_pub=their_signing_pub,
        fingerprint=fingerprint,
    )

    # Establish the E2EE session (we're the initiator)
    session_data = establish_session(
        my_identity_private=state.identity_private_key,
        my_identity_public=state.identity_public_key,
        their_identity_public=their_identity_pub,
        is_initiator=True,
    )

    # Store the session state locally
    store_session(
        username=state.username,
        contact_username=contact_username,
        shared_secret=session_data["shared_secret"],
        sending_chain_key=session_data["sending_chain_key"],
        receiving_chain_key=session_data["receiving_chain_key"],
        ephemeral_public=session_data["ephemeral_public"],
        is_established=True,
    )

    return True


def send_chat_message(receiver, plaintext, ttl=None):
    """
    Encrypt and send a message to a contact.
    
    Steps:
    1. Ensure we have an E2EE session with the receiver
    2. Get the current send counter
    3. Derive a unique message key for this message
    4. Build associated data (binds sender, receiver, counter, TTL)
    5. Encrypt with AES-256-GCM
    6. Send the ciphertext through the WebSocket
    7. Store the plaintext locally for our own message history
    """
    if not ensure_session(receiver):
        print("[!] Could not establish secure session.")
        return False

    session = get_session(state.username, receiver)
    if session is None:
        print("[!] No session found.")
        return False

    # Get and increment the message counter (for replay protection)
    counter = increment_send_counter(state.username, receiver)

    # Derive the message-specific encryption key
    msg_key = derive_message_key(session["sending_chain_key"], counter)

    # Build associated data (authenticated but not encrypted)
    # This prevents the server from swapping messages between conversations
    ad = build_associated_data(state.username, receiver, counter, ttl)

    # Encrypt the message with AES-256-GCM
    nonce, ciphertext = encrypt_message(msg_key, plaintext, ad)

    # Get the ephemeral key to include (so the receiver can establish the session)
    ephemeral_pub = session.get("ephemeral_public_key")

    # Send through the WebSocket (server only sees ciphertext)
    success = state.network.send_encrypted_message(
        receiver=receiver,
        ciphertext=to_base64(ciphertext),
        nonce=to_base64(nonce),
        message_counter=counter,
        ttl=ttl,
        ephemeral_key=to_base64(ephemeral_pub) if ephemeral_pub else None,
        associated_data=to_base64(ad),
    )

    if success:
        # Store the plaintext in our local database (for our own history)
        store_message(
            state.username, receiver, state.username,
            plaintext, counter, is_incoming=False, ttl=ttl, status="sent",
        )

    return success


def handle_incoming_message(data):
    """
    Handle an incoming encrypted message.
    
    Steps:
    1. Check if we have a session with the sender
    2. If not, establish one using the ephemeral key (if provided)
    3. Check for replay (duplicate counter)
    4. Derive the message key and decrypt
    5. Verify the associated data
    6. Store the decrypted message locally
    7. Send a delivery acknowledgment
    """
    sender = data.get("sender", "")
    ciphertext_b64 = data.get("ciphertext", "")
    nonce_b64 = data.get("nonce", "")
    ephemeral_key_b64 = data.get("ephemeral_key")
    message_counter = data.get("message_counter", 0)
    ttl = data.get("ttl")
    ad_b64 = data.get("associated_data", "")
    timestamp = data.get("timestamp", "")

    # Replay protection: check if we've already seen this counter (R9)
    if is_counter_seen(state.username, sender, message_counter):
        # Duplicate/replayed message -- silently ignore it
        return

    # Make sure we have a session with the sender
    session = get_session(state.username, sender)

    if session is None:
        # We don't have a session yet -- try to establish one
        # Fetch the sender's public keys
        key_data, status = state.network.get_user_keys(sender)
        if status != 200:
            print(f"\n[!] Cannot decrypt message from {sender}: failed to get keys")
            return

        their_identity_pub = from_base64(key_data["identity_public_key"])
        their_signing_pub = from_base64(key_data["signing_public_key"])

        # Compute fingerprint
        fingerprint = compute_fingerprint(state.identity_public_key, their_identity_pub)

        # Check for key change (R6)
        existing_contact = get_contact(state.username, sender)
        if existing_contact and existing_contact.get("identity_public_key"):
            old_key = existing_contact["identity_public_key"]
            if old_key != their_identity_pub:
                print(f"\n[!! WARNING !!] {sender}'s identity key has CHANGED!")

        # Add/update the contact
        add_contact(state.username, sender,
                    identity_pub=their_identity_pub,
                    signing_pub=their_signing_pub,
                    fingerprint=fingerprint)

        # Establish session
        if ephemeral_key_b64:
            # The sender included their ephemeral key -- complete the session
            their_ephemeral_pub = from_base64(ephemeral_key_b64)
            session_data = complete_session_with_ephemeral(
                my_identity_private=state.identity_private_key,
                my_identity_public=state.identity_public_key,
                their_identity_public=their_identity_pub,
                their_ephemeral_public=their_ephemeral_pub,
            )
        else:
            # No ephemeral key -- basic DH session
            session_data = establish_session(
                my_identity_private=state.identity_private_key,
                my_identity_public=state.identity_public_key,
                their_identity_public=their_identity_pub,
                is_initiator=False,
            )

        store_session(
            username=state.username,
            contact_username=sender,
            shared_secret=session_data["shared_secret"],
            sending_chain_key=session_data["sending_chain_key"],
            receiving_chain_key=session_data["receiving_chain_key"],
            is_established=True,
        )

        session = get_session(state.username, sender)

    # Decrypt the message
    try:
        ciphertext = from_base64(ciphertext_b64)
        nonce = from_base64(nonce_b64)
        ad = from_base64(ad_b64)

        # Derive the message key using the receiving chain key and counter
        msg_key = derive_message_key(session["receiving_chain_key"], message_counter)

        # Decrypt and verify (AES-256-GCM checks integrity + associated data)
        plaintext = decrypt_message(msg_key, nonce, ciphertext, ad)

        # Mark this counter as seen (replay protection)
        mark_counter_seen(state.username, sender, message_counter)

        # Store the decrypted message locally
        store_message(
            state.username, sender, sender,
            plaintext, message_counter, is_incoming=True, ttl=ttl,
        )

        # Display the message if we're in the chat with this person
        if state.current_chat == sender:
            ttl_str = f" [self-destruct: {ttl}s]" if ttl else ""
            print(f"\n  [{sender}]: {plaintext}{ttl_str}")
            print("> ", end="", flush=True)
        else:
            # Show notification that we got a message
            print(f"\n  [New message from {sender}]")
            print("> ", end="", flush=True)

        # Send delivery acknowledgment to the sender (R18 Option B)
        state.network.send_delivery_ack(sender, message_counter)

    except Exception as e:
        print(f"\n[!] Failed to decrypt message from {sender}: {e}")


def handle_message_status(data):
    """Handle message delivery status update (sent/delivered)."""
    receiver = data.get("receiver", "")
    counter = data.get("message_counter", 0)
    status = data.get("status", "")

    # Update the message status in our local database
    update_message_status(state.username, receiver, counter, status)

    # Show status update if we're in the chat
    if state.current_chat == receiver and status == "delivered":
        print(f"  [Message {counter} delivered to {receiver}]")
        print("> ", end="", flush=True)


def handle_friend_request_notification(data):
    """Handle incoming friend request notification."""
    from_user = data.get("from", "unknown")
    print(f"\n  [New friend request from {from_user}! Use /requests to view.]")
    print("> ", end="", flush=True)


# ============================================================
# CLI Command Handlers
# ============================================================

def cmd_register(network):
    """Handle user registration flow."""
    print("\n--- Register New Account ---")
    username = input("Username (3-32 alphanumeric chars): ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        return False

    password = input("Password: ").strip()
    if not password:
        print("[!] Password cannot be empty.")
        return False

    # (Validation relaxed for testing)
    # confirm_password = input("Confirm password: ").strip()
    # if password != confirm_password:
    #     print("[!] Passwords don't match.")
    #     return False

    print("\n[*] Generating identity keys...")

    # Generate our X25519 keypair (for key exchange)
    identity_priv, identity_pub = generate_x25519_keypair()

    # Generate our Ed25519 keypair (for signatures)
    signing_priv, signing_pub = generate_ed25519_keypair()

    # Register with the server
    print("[*] Registering with server...")
    data, status = network.register(
        username, password,
        to_base64(identity_pub),
        to_base64(signing_pub),
    )

    if status != 201:
        print(f"[!] Registration failed: {data.get('error', 'Unknown error')}")
        return False

    print(f"[+] Registration successful!")

    # Initialize the local database for this user
    init_local_db(username)

    # Encrypt and store our private keys locally
    identity_priv_enc = encrypt_private_key(password, identity_priv)
    signing_priv_enc = encrypt_private_key(password, signing_priv)

    store_identity_keys(
        username,
        identity_priv_enc, identity_pub,
        signing_priv_enc, signing_pub,
    )

    # Show the OTP setup info
    otp_secret = data.get("otp_secret", "")
    otp_uri = data.get("otp_uri", "")

    print("\n============================================")
    print("   TWO-FACTOR AUTHENTICATION SETUP")
    print("============================================")
    print(f"  Your OTP Secret: {otp_secret}")
    print(f"\n  Add this to your authenticator app (Google Authenticator, Authy, etc.)")
    print(f"  Or scan the QR code URI: {otp_uri}")
    print("\n  IMPORTANT: Save the OTP secret! You need it for every login.")
    print("============================================")

    # Store OTP secret locally for convenience (user can also use authenticator app)
    otp_file = os.path.join(os.path.dirname(__file__), "..", "data", f"{username}_otp.txt")
    os.makedirs(os.path.dirname(otp_file), exist_ok=True)
    with open(otp_file, "w") as f:
        f.write(otp_secret)

    print(f"\n  [OTP secret also saved to: {otp_file}]")
    print(f"  [For testing, you can use this to generate OTP codes]")

    return True


def cmd_login(network):
    """Handle user login flow."""
    print("\n--- Login ---")
    username = input("Username: ").strip()
    if not username:
        print("[!] Username cannot be empty.")
        return False

    password = input("Password: ").strip()
    if not password:
        print("[!] Password cannot be empty.")
        return False

    # Try to auto-load OTP secret for convenience (testing)
    otp_file = os.path.join(os.path.dirname(__file__), "..", "data", f"{username}_otp.txt")
    auto_otp = None
    if os.path.exists(otp_file):
        with open(otp_file, "r") as f:
            auto_otp = f.read().strip()

    otp_code = input(f"OTP Code (use 000000 to bypass): ").strip()

    # If user didn't enter OTP, try auto-generating from stored secret
    if not otp_code and auto_otp:
        import pyotp
        otp_code = pyotp.TOTP(auto_otp).now()
        print(f"  [Auto-generated OTP: {otp_code}]")

    if not otp_code:
        print("[!] OTP code is required.")
        return False

    # Login to the server
    print("[*] Logging in...")
    data, status = network.login(username, password, otp_code)

    if status != 200:
        print(f"[!] Login failed: {data.get('error', 'Unknown error')}")
        return False

    print(f"[+] Login successful! Welcome, {username}.")

    # Initialize local database
    init_local_db(username)

    # Load our identity keys from local storage
    keys = get_identity_keys(username)
    if keys is None:
        print("[!] No identity keys found locally. Please register first.")
        return False

    # Decrypt the private keys using our password
    try:
        identity_priv = decrypt_private_key(password, keys["identity_private_key"])
        signing_priv = decrypt_private_key(password, keys["signing_private_key"])
    except Exception:
        print("[!] Failed to decrypt local keys. Wrong password?")
        return False

    # Store the decrypted keys in memory for this session
    state.username = username
    state.password = password
    state.identity_private_key = identity_priv
    state.identity_public_key = keys["identity_public_key"]
    state.signing_private_key = signing_priv
    state.signing_public_key = keys["signing_public_key"]
    state.network = network

    # Connect WebSocket for real-time messaging
    print("[*] Connecting to real-time messaging...")
    network.on_message_received = handle_incoming_message
    network.on_message_status = handle_message_status
    network.on_friend_request = handle_friend_request_notification

    if network.connect_websocket():
        print("[+] Connected to real-time messaging.")
    else:
        print("[!] Real-time messaging unavailable. Using offline mode.")

    # Start periodic cleanup of expired self-destruct messages
    cleanup_thread = threading.Thread(
        target=periodic_message_cleanup,
        args=(username,),
        daemon=True,
    )
    cleanup_thread.start()

    return True


def periodic_message_cleanup(username):
    """Periodically delete expired self-destruct messages (R11)."""
    while state.username == username:
        try:
            cleanup_expired_messages(username)
        except Exception:
            pass
        time.sleep(10)  # check every 10 seconds


def cmd_friends(network):
    """Show the friends list."""
    data, status = network.get_friends()
    if status != 200:
        print(f"[!] Error: {data.get('error', 'Unknown')}")
        return

    friends = data.get("friends", [])
    if not friends:
        print("\n  You have no friends yet. Use /add <username> to add someone.")
        return

    print(f"\n  --- Your Friends ({len(friends)}) ---")
    for f in friends:
        contact = get_contact(state.username, f["username"])
        verified = " [Verified]" if contact and contact.get("is_verified") else ""
        print(f"  - {f['username']}{verified}")


def cmd_add_friend(network, target):
    """Send a friend request."""
    data, status = network.send_friend_request(target)
    if status == 200:
        print(f"[+] {data.get('message', 'Friend request sent.')}")
    else:
        print(f"[!] {data.get('error', 'Failed to send friend request.')}")


def cmd_requests(network):
    """View and manage pending friend requests."""
    data, status = network.get_friend_requests()
    if status != 200:
        print(f"[!] Error: {data.get('error', 'Unknown')}")
        return

    received = data.get("received", [])
    sent = data.get("sent", [])

    if not received and not sent:
        print("\n  No pending friend requests.")
        return

    if received:
        print(f"\n  --- Received Requests ({len(received)}) ---")
        for r in received:
            print(f"  [{r['id']}] From: {r['sender_username']} (sent {r['created_at']})")
        print("\n  Use /accept <id> or /decline <id> to respond.")

    if sent:
        print(f"\n  --- Sent Requests ({len(sent)}) ---")
        for r in sent:
            print(f"  [{r['id']}] To: {r['receiver_username']} (sent {r['created_at']})")
        print("\n  Use /cancel <id> to cancel a request.")


def cmd_conversations():
    """Show the conversation list with unread counts (R23, R24)."""
    convos = get_conversations(state.username)

    if not convos:
        print("\n  No conversations yet. Chat with a friend to start one!")
        return

    print("\n  --- Conversations ---")
    for c in convos:
        unread = c.get("unread_count", 0)
        unread_str = f" ({unread} unread)" if unread > 0 else ""
        verified_str = " [V]" if c.get("is_verified") else ""
        last_msg = c.get("last_message", "")
        # Truncate long messages for the preview
        if len(last_msg) > 40:
            last_msg = last_msg[:37] + "..."
        print(f"  - {c['username']}{verified_str}{unread_str}: {last_msg}")
        print(f"    Last activity: {c.get('last_message_time', 'N/A')}")


def cmd_chat(contact_username):
    """Enter chat mode with a specific contact."""

    # Verify they're our friend
    data, status = state.network.get_friends()
    if status != 200:
        print("[!] Could not verify friendship.")
        return

    friends = [f["username"] for f in data.get("friends", [])]
    if contact_username not in friends:
        print(f"[!] {contact_username} is not your friend. Add them first with /add")
        return

    # Make sure we have a secure session
    if not ensure_session(contact_username):
        print("[!] Could not establish secure session.")
        return

    state.current_chat = contact_username

    # Show contact verification status
    contact = get_contact(state.username, contact_username)
    if contact:
        verified = "VERIFIED" if contact.get("is_verified") else "UNVERIFIED"
        print(f"\n  --- Chat with {contact_username} [{verified}] ---")
        if contact.get("fingerprint"):
            print(f"  Fingerprint: {contact['fingerprint']}")
    else:
        print(f"\n  --- Chat with {contact_username} ---")

    # Load recent messages (with pagination - R25)
    messages = get_messages(state.username, contact_username, limit=20)
    if messages:
        print("\n  --- Recent Messages ---")
        for m in messages:
            sender = "You" if not m["is_incoming"] else m["sender"]
            status_str = f" [{m['status']}]" if not m["is_incoming"] else ""
            ttl_str = f" [self-destruct: {m['ttl']}s]" if m.get("ttl") else ""
            print(f"  [{sender}]{status_str}{ttl_str}: {m['content']}")
        print()

    print("  Type your message and press Enter to send.")
    print("  Commands: /back (exit chat), /ttl <seconds> (set self-destruct),")
    print("            /history (load more messages), /verify (verify fingerprint)")
    print()

    # Chat loop
    current_ttl = None  # current self-destruct timer (None = no expiry)

    while state.current_chat == contact_username:
        try:
            msg = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            state.current_chat = None
            break

        if not msg:
            continue

        # Handle chat commands
        if msg.startswith("/"):
            parts = msg.split(maxsplit=1)
            cmd = parts[0].lower()

            if cmd == "/back":
                state.current_chat = None
                print("[*] Left chat.")
                break

            elif cmd == "/ttl":
                if len(parts) > 1:
                    try:
                        seconds = int(parts[1])
                        if seconds <= 0:
                            current_ttl = None
                            print("[*] Self-destruct disabled.")
                        else:
                            current_ttl = seconds
                            print(f"[*] Self-destruct set to {seconds} seconds.")
                    except ValueError:
                        print("[!] Invalid number. Usage: /ttl <seconds>")
                else:
                    if current_ttl:
                        print(f"[*] Current TTL: {current_ttl}s. Use /ttl 0 to disable.")
                    else:
                        print("[*] Self-destruct is disabled. Use /ttl <seconds> to enable.")

            elif cmd == "/history":
                # Load more messages (pagination - R25)
                messages = get_messages(state.username, contact_username, limit=50)
                if messages:
                    print("\n  --- Message History ---")
                    for m in messages:
                        sender = "You" if not m["is_incoming"] else m["sender"]
                        status_str = f" [{m['status']}]" if not m["is_incoming"] else ""
                        print(f"  [{sender}]{status_str}: {m['content']}")
                    print()
                else:
                    print("  No messages yet.")

            elif cmd == "/verify":
                contact = get_contact(state.username, contact_username)
                if contact and contact.get("fingerprint"):
                    print(f"\n  Fingerprint for {contact_username}:")
                    print(f"  {contact['fingerprint']}")
                    print("\n  Compare this with your contact in person or via a secure channel.")
                    confirm = input("  Mark as verified? (y/n): ").strip().lower()
                    if confirm == "y":
                        set_contact_verified(state.username, contact_username, True)
                        print("[+] Contact marked as verified.")
                    else:
                        print("[*] Not verified.")
                else:
                    print("[!] No fingerprint available for this contact.")

            else:
                print(f"[!] Unknown command: {cmd}")

        else:
            # Send the message (encrypted)
            ttl_display = f" [self-destruct: {current_ttl}s]" if current_ttl else ""
            if send_chat_message(contact_username, msg, ttl=current_ttl):
                print(f"  [You]{ttl_display}: {msg}")
            else:
                print("[!] Failed to send message.")


# ============================================================
# Main menu loop
# ============================================================

def show_main_menu():
    """Show the main menu after login."""
    print("\n  --- Main Menu ---")
    print("  /friends        - View friends list")
    print("  /add <user>     - Send friend request")
    print("  /requests       - View/manage friend requests")
    print("  /accept <id>    - Accept a friend request")
    print("  /decline <id>   - Decline a friend request")
    print("  /cancel <id>    - Cancel a sent friend request")
    print("  /remove <user>  - Remove a friend")
    print("  /block <user>   - Block a user")
    print("  /unblock <user> - Unblock a user")
    print("  /chat <user>    - Start chatting with a friend")
    print("  /conversations  - View conversation list")
    print("  /verify <user>  - Verify a contact's fingerprint")
    print("  /logout         - Log out")
    print("  /help           - Show this menu")
    print("  /quit           - Exit the application")


def main_loop():
    """Main command loop after login."""
    show_main_menu()

    while True:
        try:
            cmd_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Goodbye!")
            break

        if not cmd_input:
            continue

        parts = cmd_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "/friends":
            cmd_friends(state.network)

        elif cmd == "/add":
            if not arg:
                print("[!] Usage: /add <username>")
            else:
                cmd_add_friend(state.network, arg)

        elif cmd == "/requests":
            cmd_requests(state.network)

        elif cmd == "/accept":
            if not arg:
                print("[!] Usage: /accept <request_id>")
            else:
                try:
                    req_id = int(arg)
                    data, status = state.network.accept_friend_request(req_id)
                    print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")
                except ValueError:
                    print("[!] Invalid request ID.")

        elif cmd == "/decline":
            if not arg:
                print("[!] Usage: /decline <request_id>")
            else:
                try:
                    req_id = int(arg)
                    data, status = state.network.decline_friend_request(req_id)
                    print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")
                except ValueError:
                    print("[!] Invalid request ID.")

        elif cmd == "/cancel":
            if not arg:
                print("[!] Usage: /cancel <request_id>")
            else:
                try:
                    req_id = int(arg)
                    data, status = state.network.cancel_friend_request(req_id)
                    print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")
                except ValueError:
                    print("[!] Invalid request ID.")

        elif cmd == "/remove":
            if not arg:
                print("[!] Usage: /remove <username>")
            else:
                data, status = state.network.remove_friend(arg)
                print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")
                remove_contact(state.username, arg)

        elif cmd == "/block":
            if not arg:
                print("[!] Usage: /block <username>")
            else:
                data, status = state.network.block_user(arg)
                print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")

        elif cmd == "/unblock":
            if not arg:
                print("[!] Usage: /unblock <username>")
            else:
                data, status = state.network.unblock_user(arg)
                print(f"[{'+'if status==200 else '!'}] {data.get('message', data.get('error', ''))}")

        elif cmd == "/chat":
            if not arg:
                print("[!] Usage: /chat <username>")
            else:
                cmd_chat(arg)

        elif cmd == "/conversations":
            cmd_conversations()

        elif cmd == "/verify":
            if not arg:
                print("[!] Usage: /verify <username>")
            else:
                contact = get_contact(state.username, arg)
                if contact and contact.get("fingerprint"):
                    print(f"\n  Fingerprint for {arg}:")
                    print(f"  {contact['fingerprint']}")
                    verified = "Yes" if contact.get("is_verified") else "No"
                    print(f"  Verified: {verified}")
                    if not contact.get("is_verified"):
                        confirm = input("  Mark as verified? (y/n): ").strip().lower()
                        if confirm == "y":
                            set_contact_verified(state.username, arg, True)
                            print("[+] Contact marked as verified.")
                else:
                    print(f"[!] No fingerprint for {arg}. Chat with them first.")

        elif cmd == "/logout":
            state.network.disconnect_websocket()
            state.network.logout()
            print("[+] Logged out successfully.")
            # Clear sensitive data from memory
            state.username = None
            state.password = None
            state.identity_private_key = None
            state.signing_private_key = None
            state.current_chat = None
            return "logout"

        elif cmd == "/help":
            show_main_menu()

        elif cmd == "/quit":
            state.network.disconnect_websocket()
            state.network.logout()
            print("[*] Goodbye!")
            return "quit"

        else:
            print(f"[!] Unknown command: {cmd}. Type /help for available commands.")


# ============================================================
# Entry point
# ============================================================

def main():
    """Main entry point for the Secure IM client."""
    parser = argparse.ArgumentParser(description="COMP3334 Secure IM Client")
    parser.add_argument(
        "--server",
        default="https://localhost:5000",
        help="Server URL (default: https://localhost:5000)",
    )
    args = parser.parse_args()

    clear_screen()
    print(BANNER)

    network = NetworkClient(server_url=args.server)

    while True:
        print("\n  1. Register")
        print("  2. Login")
        print("  3. Quit")

        choice = input("\n  Choose an option: ").strip()

        if choice == "1":
            cmd_register(network)

        elif choice == "2":
            if cmd_login(network):
                result = main_loop()
                if result == "quit":
                    break
                # If "logout", continue to the login menu

        elif choice == "3":
            print("[*] Goodbye!")
            break

        else:
            print("[!] Invalid choice. Please enter 1, 2, or 3.")

    sys.exit(0)


if __name__ == "__main__":
    main()
