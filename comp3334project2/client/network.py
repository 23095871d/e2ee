"""
network.py - Network communication layer for the Secure IM client.

This module handles all communication with the server:
- HTTPS REST API calls (registration, login, friend management)
- WebSocket connection for real-time messaging (via Socket.IO)

All connections use TLS (HTTPS/WSS) to protect against network attackers.
The client verifies the server's TLS certificate using our self-signed CA cert.

Note: Even though TLS protects the transport layer, we still use E2EE
for message contents because the server is honest-but-curious and might
inspect data at the application layer.
"""

import os
import ssl
import json
import requests
import socketio
import threading

# Path to our CA certificate (for verifying the server's TLS cert)
CA_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "certs", "ca_cert.pem")


class NetworkClient:
    """
    Handles all network communication with the Secure IM server.
    Uses HTTPS for REST API calls and WebSocket (Socket.IO) for real-time messaging.
    """

    def __init__(self, server_url="https://localhost:5000"):
        self.server_url = server_url
        self.auth_token = None  # set after login
        self.sio = None         # Socket.IO client (created on connect)

        # Callbacks for incoming WebSocket events (set by the main app)
        self.on_message_received = None
        self.on_message_sent_ack = None
        self.on_message_status = None
        self.on_friend_request = None
        self.on_typing = None
        self.on_disconnect_callback = None

    # ============================================================
    # HTTP API calls (REST)
    # ============================================================

    def _headers(self):
        """Build HTTP headers with auth token if available."""
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _get_verify(self):
        """Get the CA cert path for TLS verification."""
        if os.path.exists(CA_CERT_PATH):
            return CA_CERT_PATH
        # Fall back to no verification if CA cert is missing (dev only)
        return False

    def register(self, username, password, identity_public_key, signing_public_key):
        """
        Register a new user account.
        Returns the response JSON (includes OTP secret for 2FA setup).
        """
        try:
            resp = requests.post(
                f"{self.server_url}/api/register",
                json={
                    "username": username,
                    "password": password,
                    "identity_public_key": identity_public_key,
                    "signing_public_key": signing_public_key,
                },
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except requests.exceptions.ConnectionError:
            return {"error": "Cannot connect to server. Is it running?"}, 0
        except Exception as e:
            return {"error": str(e)}, 0

    def login(self, username, password, otp_code):
        """
        Log in with username + password + OTP code.
        Stores the auth token on success.
        """
        try:
            resp = requests.post(
                f"{self.server_url}/api/login",
                json={
                    "username": username,
                    "password": password,
                    "otp_code": otp_code,
                },
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                self.auth_token = data.get("token")
            return data, resp.status_code
        except requests.exceptions.ConnectionError:
            return {"error": "Cannot connect to server. Is it running?"}, 0
        except Exception as e:
            return {"error": str(e)}, 0

    def logout(self):
        """Log out and invalidate the session token."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/logout",
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            self.auth_token = None
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def get_user_keys(self, username):
        """Fetch a user's public keys from the server."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/keys/{username}",
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def update_keys(self, identity_public_key, signing_public_key):
        """Update our public keys on the server (key rotation)."""
        try:
            resp = requests.put(
                f"{self.server_url}/api/keys",
                json={
                    "identity_public_key": identity_public_key,
                    "signing_public_key": signing_public_key,
                },
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def send_friend_request(self, target_username):
        """Send a friend request to another user."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/request",
                json={"username": target_username},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def get_friend_requests(self):
        """Get pending friend requests (received and sent)."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/friends/requests",
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def accept_friend_request(self, request_id):
        """Accept a friend request."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/accept",
                json={"request_id": request_id},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def decline_friend_request(self, request_id):
        """Decline a friend request."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/decline",
                json={"request_id": request_id},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def cancel_friend_request(self, request_id):
        """Cancel a sent friend request."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/cancel",
                json={"request_id": request_id},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def get_friends(self):
        """Get the friends list."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/friends",
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def remove_friend(self, username):
        """Remove a friend."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/remove",
                json={"username": username},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def block_user(self, username):
        """Block a user."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/block",
                json={"username": username},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def unblock_user(self, username):
        """Unblock a user."""
        try:
            resp = requests.post(
                f"{self.server_url}/api/friends/unblock",
                json={"username": username},
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    def get_offline_messages(self):
        """Fetch offline messages from the server."""
        try:
            resp = requests.get(
                f"{self.server_url}/api/offline-messages",
                headers=self._headers(),
                verify=self._get_verify(),
                timeout=10,
            )
            return resp.json(), resp.status_code
        except Exception as e:
            return {"error": str(e)}, 0

    # ============================================================
    # WebSocket (Socket.IO) for real-time messaging
    # ============================================================

    def connect_websocket(self):
        """
        Establish a WebSocket connection to the server for real-time messaging.
        The connection runs in a background thread so it doesn't block the CLI.
        """
        if self.sio is not None:
            try:
                self.sio.disconnect()
            except Exception:
                pass

        # Create a new Socket.IO client with TLS support
        ssl_context = ssl.create_default_context()
        if os.path.exists(CA_CERT_PATH):
            ssl_context.load_verify_locations(CA_CERT_PATH)
        else:
            # Disable verification for development (not for production!)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self.sio = socketio.Client(
            ssl_verify=False,  # we handle SSL context manually
            logger=False,
            engineio_logger=False,
        )

        # Register event handlers
        self._setup_socket_handlers()

        try:
            self.sio.connect(
                self.server_url,
                transports=["websocket"],
                wait_timeout=10,
            )

            # Authenticate the WebSocket connection with our token
            self.sio.emit("authenticate", {"token": self.auth_token})
            return True
        except Exception as e:
            print(f"[!] WebSocket connection failed: {e}")
            return False

    def _setup_socket_handlers(self):
        """Set up handlers for incoming WebSocket events."""

        @self.sio.on("authenticated")
        def on_authenticated(data):
            pass  # authentication confirmed

        @self.sio.on("auth_error")
        def on_auth_error(data):
            print(f"\n[!] WebSocket auth error: {data.get('error', 'Unknown')}")

        @self.sio.on("receive_message")
        def on_message(data):
            # Forward to the callback set by main.py
            if self.on_message_received:
                self.on_message_received(data)

        @self.sio.on("message_sent")
        def on_sent(data):
            if self.on_message_sent_ack:
                self.on_message_sent_ack(data)

        @self.sio.on("message_status")
        def on_status(data):
            if self.on_message_status:
                self.on_message_status(data)

        @self.sio.on("friend_request_received")
        def on_friend_req(data):
            if self.on_friend_request:
                self.on_friend_request(data)

        @self.sio.on("user_typing")
        def on_typing(data):
            if self.on_typing:
                self.on_typing(data)

        @self.sio.on("error")
        def on_error(data):
            print(f"\n[!] Server error: {data.get('error', 'Unknown')}")

        @self.sio.on("disconnect")
        def on_disconnect():
            if self.on_disconnect_callback:
                self.on_disconnect_callback()

    def send_encrypted_message(self, receiver, ciphertext, nonce,
                                message_counter, ttl=None,
                                ephemeral_key=None, associated_data=None):
        """
        Send an encrypted message through the WebSocket.
        The server only sees ciphertext -- it cannot decrypt the message.
        """
        if self.sio is None or not self.sio.connected:
            print("[!] Not connected to server.")
            return False

        self.sio.emit("send_message", {
            "receiver": receiver,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "message_counter": message_counter,
            "ttl": ttl,
            "ephemeral_key": ephemeral_key,
            "associated_data": associated_data,
        })
        return True

    def send_delivery_ack(self, sender, message_counter):
        """Send a delivery acknowledgment back to the message sender."""
        if self.sio and self.sio.connected:
            self.sio.emit("message_delivered_ack", {
                "sender": sender,
                "message_counter": message_counter,
            })

    def send_typing(self, receiver):
        """Send a typing indicator to the chat partner."""
        if self.sio and self.sio.connected:
            self.sio.emit("typing", {"receiver": receiver})

    def disconnect_websocket(self):
        """Disconnect the WebSocket connection."""
        if self.sio:
            try:
                self.sio.disconnect()
            except Exception:
                pass
            self.sio = None
