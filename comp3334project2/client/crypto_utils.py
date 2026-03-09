"""
crypto_utils.py - Cryptographic operations for the Secure IM client.

This module implements all the cryptographic primitives needed for E2EE:

1. KEY GENERATION:
   - X25519 keypairs for Diffie-Hellman key agreement
   - Ed25519 keypairs for digital signatures

2. SESSION ESTABLISHMENT (simplified X3DH-like protocol):
   - When Alice wants to talk to Bob:
     a) Alice generates an ephemeral X25519 keypair
     b) Computes DH(alice_identity, bob_identity) || DH(alice_ephemeral, bob_identity)
     c) Derives shared secret via HKDF
     d) Both sides derive sending/receiving chain keys
   - Bob performs the same DH computations to get the same shared secret

3. MESSAGE ENCRYPTION:
   - AES-256-GCM (authenticated encryption with associated data)
   - Each message gets a unique key derived from the chain key + counter
   - Associated data binds sender, receiver, counter, and TTL

4. REPLAY PROTECTION:
   - Message counters per conversation
   - Clients track seen counters and reject duplicates

5. KEY STORAGE:
   - Private keys are encrypted at rest using a key derived from the user's password
   - Uses AES-256-GCM for encrypting stored keys

Cryptographic library: Python 'cryptography' (version 44.0.0)
- Well-reviewed, widely used, maintained by PyCA
- Uses OpenSSL under the hood for all primitives

Security properties provided:
- E2E confidentiality (server never sees plaintext)
- E2E integrity and authentication (AES-GCM + identity key binding)
- Replay resistance (message counters)

Limitations:
- No Double Ratchet (no per-message forward secrecy after session establishment)
- Session compromise reveals future messages (until new session)
"""

import os
import base64
import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ============================================================
# Key Generation
# ============================================================

def generate_x25519_keypair():
    """
    Generate an X25519 key pair for Diffie-Hellman key exchange.
    
    X25519 is an elliptic curve Diffie-Hellman function using Curve25519.
    It's fast, secure, and widely used (Signal, WhatsApp, TLS 1.3).
    
    Returns:
        (private_key_bytes, public_key_bytes): tuple of 32-byte keys
    """
    private_key = X25519PrivateKey.generate()

    # Serialize the keys to raw bytes (32 bytes each)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


def generate_ed25519_keypair():
    """
    Generate an Ed25519 key pair for digital signatures.
    
    Ed25519 is used to sign messages and verify authenticity.
    It provides non-repudiation: the receiver can verify who sent a message.
    
    Returns:
        (private_key_bytes, public_key_bytes): 32-byte private, 32-byte public
    """
    private_key = Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


# ============================================================
# Diffie-Hellman Key Exchange
# ============================================================

def perform_dh(private_key_bytes, public_key_bytes):
    """
    Perform an X25519 Diffie-Hellman key exchange.
    
    Given our private key and the other party's public key,
    compute a shared secret. Both parties will compute the
    same shared secret independently.
    
    Args:
        private_key_bytes: our X25519 private key (32 bytes)
        public_key_bytes: their X25519 public key (32 bytes)
    
    Returns:
        shared_secret: 32 bytes of shared secret material
    """
    private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key = X25519PublicKey.from_public_bytes(public_key_bytes)

    # X25519 DH produces a 32-byte shared secret
    return private_key.exchange(public_key)


# ============================================================
# Key Derivation (HKDF)
# ============================================================

def derive_key(input_key_material, info, salt=None, length=32):
    """
    Derive a cryptographic key using HKDF-SHA256.
    
    HKDF (HMAC-based Key Derivation Function) is the standard way
    to derive strong keys from shared secrets. It's used in TLS 1.3,
    Signal Protocol, and many other systems.
    
    Args:
        input_key_material: the raw key material (e.g., DH shared secret)
        info: context string (e.g., "message_key" or "chain_key")
        salt: optional salt (random bytes for extra security)
        length: desired output key length in bytes (default 32 = 256 bits)
    
    Returns:
        derived key of the specified length
    """
    if isinstance(info, str):
        info = info.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


# ============================================================
# Session Establishment
# ============================================================

def establish_session(my_identity_private, my_identity_public,
                      their_identity_public, is_initiator):
    """
    Establish an E2EE session with another user.
    
    Protocol (simplified X3DH-like):
    1. Compute DH(my_identity, their_identity) for mutual authentication
    2. If initiator: generate ephemeral key, compute DH(ephemeral, their_identity)
    3. Combine DH outputs and derive session keys via HKDF
    
    The initiator (Alice) generates an ephemeral key for some forward secrecy.
    The responder (Bob) uses the ephemeral key sent by Alice.
    
    Args:
        my_identity_private: our X25519 private key
        my_identity_public: our X25519 public key
        their_identity_public: their X25519 public key
        is_initiator: True if we're starting the conversation
    
    Returns:
        dict with: shared_secret, sending_chain_key, receiving_chain_key,
                   ephemeral_public (only if initiator)
    """
    # Step 1: Identity-to-Identity DH (mutual authentication)
    dh1 = perform_dh(my_identity_private, their_identity_public)

    ephemeral_public = None
    ephemeral_private = None

    if is_initiator:
        # Step 2: Generate ephemeral key for forward secrecy
        ephemeral_private, ephemeral_public = generate_x25519_keypair()
        dh2 = perform_dh(ephemeral_private, their_identity_public)
        # Combine both DH outputs
        combined = dh1 + dh2
    else:
        # Responder only does identity DH (ephemeral DH comes later)
        combined = dh1

    # Step 3: Derive the root shared secret using HKDF
    # Salt uses both public keys sorted for consistency
    # (both parties must derive the same salt)
    sorted_keys = sorted([my_identity_public, their_identity_public])
    salt = sorted_keys[0] + sorted_keys[1]

    shared_secret = derive_key(
        input_key_material=combined,
        info="comp3334_secure_im_session_v1",
        salt=salt,
    )

    # Step 4: Derive separate chain keys for each direction
    # This ensures messages in each direction use different keys
    # We use the sorted public keys to determine which chain is which
    if my_identity_public == sorted_keys[0]:
        # We're "party A" (lexicographically first key)
        sending_chain = derive_key(shared_secret, info="chain_a_to_b")
        receiving_chain = derive_key(shared_secret, info="chain_b_to_a")
    else:
        # We're "party B"
        sending_chain = derive_key(shared_secret, info="chain_b_to_a")
        receiving_chain = derive_key(shared_secret, info="chain_a_to_b")

    return {
        "shared_secret": shared_secret,
        "sending_chain_key": sending_chain,
        "receiving_chain_key": receiving_chain,
        "ephemeral_public": ephemeral_public,
    }


def complete_session_with_ephemeral(my_identity_private, my_identity_public,
                                     their_identity_public, their_ephemeral_public):
    """
    Complete session establishment using the initiator's ephemeral key.
    
    Called by the responder (Bob) when receiving Alice's first message
    that includes her ephemeral public key.
    
    This computes:
    - DH(bob_identity, alice_identity) [same as both sides]
    - DH(bob_identity, alice_ephemeral) [forward secrecy component]
    
    Args:
        my_identity_private: our X25519 private key
        my_identity_public: our X25519 public key
        their_identity_public: their X25519 public key
        their_ephemeral_public: their ephemeral X25519 public key
    
    Returns:
        dict with session keys (same format as establish_session)
    """
    # Both DH computations
    dh1 = perform_dh(my_identity_private, their_identity_public)
    dh2 = perform_dh(my_identity_private, their_ephemeral_public)
    combined = dh1 + dh2

    # Same key derivation as the initiator
    sorted_keys = sorted([my_identity_public, their_identity_public])
    salt = sorted_keys[0] + sorted_keys[1]

    shared_secret = derive_key(
        input_key_material=combined,
        info="comp3334_secure_im_session_v1",
        salt=salt,
    )

    if my_identity_public == sorted_keys[0]:
        sending_chain = derive_key(shared_secret, info="chain_a_to_b")
        receiving_chain = derive_key(shared_secret, info="chain_b_to_a")
    else:
        sending_chain = derive_key(shared_secret, info="chain_b_to_a")
        receiving_chain = derive_key(shared_secret, info="chain_a_to_b")

    return {
        "shared_secret": shared_secret,
        "sending_chain_key": sending_chain,
        "receiving_chain_key": receiving_chain,
    }


# ============================================================
# Message Key Derivation (Symmetric Ratchet)
# ============================================================

def derive_message_key(chain_key, counter):
    """
    Derive a unique message key from the chain key and counter.
    
    This is a simple symmetric ratchet: each message gets a unique
    key derived from the chain key and an incrementing counter.
    This provides some forward secrecy for individual messages --
    learning one message key doesn't reveal others.
    
    Args:
        chain_key: the chain key for this direction (32 bytes)
        counter: message counter (integer, incremented per message)
    
    Returns:
        32-byte message key for AES-256-GCM
    """
    # Pack the counter as a big-endian 8-byte integer
    counter_bytes = struct.pack(">Q", counter)

    return derive_key(
        input_key_material=chain_key,
        info=b"message_key_" + counter_bytes,
    )


# ============================================================
# Message Encryption / Decryption (AES-256-GCM)
# ============================================================

def encrypt_message(message_key, plaintext, associated_data):
    """
    Encrypt a message using AES-256-GCM (authenticated encryption).
    
    AES-256-GCM provides both confidentiality AND integrity:
    - Confidentiality: only someone with the key can read the message
    - Integrity: any tampering with ciphertext or associated data is detected
    
    The associated data (AD) is authenticated but not encrypted. We use it
    to bind metadata (sender, receiver, counter, TTL) to the ciphertext,
    so the server can't swap messages between conversations undetected.
    
    Args:
        message_key: 32-byte AES-256 key
        plaintext: the message text (string)
        associated_data: metadata to authenticate (bytes)
    
    Returns:
        (nonce, ciphertext): 12-byte nonce and encrypted message bytes
    """
    # Generate a random 96-bit (12-byte) nonce
    # CRITICAL: nonce must be unique for each message with the same key
    # Using os.urandom (CSPRNG) makes collisions negligibly unlikely
    nonce = os.urandom(12)

    # Create the AES-GCM cipher with our 256-bit key
    aesgcm = AESGCM(message_key)

    # Encrypt the plaintext and authenticate the associated data
    plaintext_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

    return nonce, ciphertext


def decrypt_message(message_key, nonce, ciphertext, associated_data):
    """
    Decrypt and verify a message using AES-256-GCM.
    
    This verifies both the ciphertext integrity AND the associated data.
    If anything was tampered with, an InvalidTag exception is raised.
    
    Args:
        message_key: 32-byte AES-256 key
        nonce: 12-byte nonce used during encryption
        ciphertext: the encrypted message bytes
        associated_data: the same metadata used during encryption
    
    Returns:
        plaintext string
    
    Raises:
        cryptography.exceptions.InvalidTag: if ciphertext or AD was tampered with
    """
    aesgcm = AESGCM(message_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext_bytes.decode("utf-8")


# ============================================================
# Associated Data Construction
# ============================================================

def build_associated_data(sender, receiver, counter, ttl=None):
    """
    Build the associated data (AD) for AES-GCM encryption.
    
    The AD binds the ciphertext to its context so that:
    - A message can't be redirected to a different receiver
    - The counter can't be changed (replay protection)
    - The TTL can't be modified without detection
    
    Args:
        sender: sender's username
        receiver: receiver's username
        counter: message counter (int)
        ttl: time-to-live in seconds (int or None)
    
    Returns:
        bytes: the associated data
    """
    ttl_value = ttl if ttl is not None else 0
    # Format: "sender|receiver|counter|ttl"
    ad_string = f"{sender}|{receiver}|{counter}|{ttl_value}"
    return ad_string.encode("utf-8")


# ============================================================
# Digital Signatures (Ed25519)
# ============================================================

def sign_data(signing_private_key_bytes, data):
    """
    Sign data using Ed25519.
    Used to prove that a message came from us (non-repudiation).
    
    Args:
        signing_private_key_bytes: 32-byte Ed25519 private key
        data: bytes to sign
    
    Returns:
        64-byte signature
    """
    private_key = Ed25519PrivateKey.from_private_bytes(signing_private_key_bytes)
    if isinstance(data, str):
        data = data.encode("utf-8")
    return private_key.sign(data)


def verify_signature(signing_public_key_bytes, data, signature):
    """
    Verify an Ed25519 signature.
    
    Args:
        signing_public_key_bytes: 32-byte Ed25519 public key
        data: the original data that was signed
        signature: 64-byte signature to verify
    
    Returns:
        True if valid, False if invalid
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(signing_public_key_bytes)
        if isinstance(data, str):
            data = data.encode("utf-8")
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


# ============================================================
# Fingerprint / Safety Number (R5)
# ============================================================

def compute_fingerprint(public_key_a, public_key_b):
    """
    Compute a human-readable fingerprint (safety number) for a conversation.
    
    Both users should see the same fingerprint. They can compare it
    out-of-band (in person, phone call) to verify they're talking to
    the right person and not a MITM attacker.
    
    The fingerprint is computed by hashing both public keys (sorted
    for consistency) and formatting as groups of 5 digits.
    
    Args:
        public_key_a: first user's identity public key (bytes)
        public_key_b: second user's identity public key (bytes)
    
    Returns:
        string like "12345 67890 11111 22222 33333 44444"
    """
    # Sort keys so both parties compute the same fingerprint
    sorted_keys = sorted([public_key_a, public_key_b])
    combined = sorted_keys[0] + sorted_keys[1]

    # Hash with SHA-256 and take enough bytes for a readable fingerprint
    digest = hashlib.sha256(combined).digest()

    # Convert to groups of 5 digits (similar to Signal's safety numbers)
    numbers = []
    for i in range(0, 30, 5):
        # Take 5 bytes, convert to integer, mod 100000 for 5 digits
        chunk = int.from_bytes(digest[i:i+5], "big")
        numbers.append(f"{chunk % 100000:05d}")

    return " ".join(numbers)


# ============================================================
# Local Key Storage Encryption
# ============================================================

def derive_storage_key(password, salt):
    """
    Derive an encryption key from the user's password for local key storage.
    
    Uses HKDF with the password and a random salt to produce a key
    for encrypting private keys at rest. This protects keys if the
    device storage is compromised.
    
    Note: For stronger protection, Argon2id or scrypt would be better
    here, but we use HKDF for simplicity since the password is also
    used server-side with Argon2id.
    
    Args:
        password: the user's password string
        salt: random salt bytes (stored alongside the encrypted keys)
    
    Returns:
        32-byte encryption key
    """
    return derive_key(
        input_key_material=password.encode("utf-8"),
        info="local_key_storage_v1",
        salt=salt,
        length=32,
    )


def encrypt_private_key(password, private_key_bytes):
    """
    Encrypt a private key for secure local storage.
    
    Args:
        password: user's password for key derivation
        private_key_bytes: the raw private key bytes to encrypt
    
    Returns:
        dict with: salt, nonce, ciphertext (all base64-encoded)
    """
    # Generate a random salt for key derivation
    salt = os.urandom(16)
    storage_key = derive_storage_key(password, salt)

    # Encrypt the private key with AES-256-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(storage_key)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, b"private_key_storage")

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_private_key(password, encrypted_data):
    """
    Decrypt a private key from local storage.
    
    Args:
        password: user's password
        encrypted_data: dict with salt, nonce, ciphertext (base64-encoded)
    
    Returns:
        raw private key bytes
    
    Raises:
        Exception if password is wrong (AEAD tag verification fails)
    """
    salt = base64.b64decode(encrypted_data["salt"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    storage_key = derive_storage_key(password, salt)

    aesgcm = AESGCM(storage_key)
    return aesgcm.decrypt(nonce, ciphertext, b"private_key_storage")


# ============================================================
# Utility functions for encoding/decoding
# ============================================================

def to_base64(data):
    """Encode bytes to base64 string for transmission."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("utf-8")


def from_base64(b64_string):
    """Decode base64 string back to bytes."""
    return base64.b64decode(b64_string)
