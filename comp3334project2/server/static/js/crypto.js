/**
 * crypto.js - Client-side cryptographic operations for E2EE.
 *
 * All encryption/decryption happens HERE in the browser.
 * The server NEVER sees plaintext messages or private keys.
 *
 * Libraries used:
 * - TweetNaCl (nacl): X25519 key exchange, Ed25519 signatures
 * - Web Crypto API: AES-256-GCM (AEAD encryption), HKDF-SHA256 (key derivation)
 *
 * Protocol overview:
 * 1. Each user generates X25519 (key exchange) + Ed25519 (signing) keypairs
 * 2. Session establishment: DH(identity_keys) + DH(ephemeral, identity)
 * 3. Messages encrypted with AES-256-GCM using keys derived via HKDF
 * 4. Replay protection via per-conversation message counters
 * 5. Associated data binds sender, receiver, counter, and TTL
 */

const CryptoModule = (() => {

    // ============================================================
    // Key Generation
    // ============================================================

    /**
     * Generate an X25519 key pair for Diffie-Hellman key exchange.
     * Uses TweetNaCl's box keypair which is Curve25519 (same as X25519).
     */
    function generateX25519KeyPair() {
        const keyPair = nacl.box.keyPair();
        return {
            publicKey: keyPair.publicKey,   // 32 bytes
            privateKey: keyPair.secretKey,  // 32 bytes
        };
    }

    /**
     * Generate an Ed25519 key pair for digital signatures.
     * TweetNaCl returns 64-byte secretKey (seed + publicKey),
     * but we only store the 32-byte seed as the private key.
     */
    function generateEd25519KeyPair() {
        const keyPair = nacl.sign.keyPair();
        return {
            publicKey: keyPair.publicKey,               // 32 bytes
            privateKey: keyPair.secretKey.slice(0, 32),  // 32-byte seed only
        };
    }

    // ============================================================
    // Diffie-Hellman Key Exchange
    // ============================================================

    /**
     * Perform X25519 Diffie-Hellman key exchange.
     * Both parties compute the same shared secret independently.
     */
    function performDH(privateKey, publicKey) {
        // nacl.scalarMult performs raw X25519 scalar multiplication
        return nacl.scalarMult(privateKey, publicKey);
    }

    // ============================================================
    // HKDF Key Derivation (using Web Crypto API)
    // ============================================================

    /**
     * Derive a cryptographic key using HKDF-SHA256.
     * This must produce identical output to the Python implementation
     * using the same parameters.
     *
     * @param {Uint8Array} ikm - Input key material
     * @param {string|Uint8Array} info - Context/purpose string
     * @param {Uint8Array|null} salt - Optional salt (null = 32 zero bytes)
     * @param {number} length - Output length in bytes (default 32)
     * @returns {Promise<Uint8Array>} Derived key
     */
    async function deriveKey(ikm, info, salt = null, length = 32) {
        // Convert info to bytes if it's a string
        if (typeof info === 'string') {
            info = new TextEncoder().encode(info);
        }
        // Convert salt to bytes if string, or use 32 zero bytes if null
        // (matches Python cryptography's HKDF behavior with salt=None)
        if (typeof salt === 'string') {
            salt = new TextEncoder().encode(salt);
        }
        if (!salt) {
            salt = new Uint8Array(32);
        }

        // Import the input key material into Web Crypto
        const keyMaterial = await crypto.subtle.importKey(
            'raw', ikm, 'HKDF', false, ['deriveBits']
        );

        // Derive bits using HKDF-SHA256
        const derived = await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: info },
            keyMaterial,
            length * 8  // length in bits
        );

        return new Uint8Array(derived);
    }

    // ============================================================
    // Session Establishment (simplified X3DH-like protocol)
    // ============================================================

    /**
     * Compare two Uint8Arrays lexicographically (for consistent key ordering).
     */
    function compareBytes(a, b) {
        for (let i = 0; i < Math.min(a.length, b.length); i++) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return a.length - b.length;
    }

    /**
     * Sort two public keys and concatenate them.
     * Both parties do this to derive the same salt.
     */
    function sortAndConcatKeys(keyA, keyB) {
        const sorted = compareBytes(keyA, keyB) <= 0 ? [keyA, keyB] : [keyB, keyA];
        const result = new Uint8Array(sorted[0].length + sorted[1].length);
        result.set(sorted[0], 0);
        result.set(sorted[1], sorted[0].length);
        return { sorted, combined: result };
    }

    /**
     * Establish an E2EE session with another user.
     *
     * If we are the initiator:
     *   - Generate an ephemeral X25519 keypair
     *   - Compute: DH(our_identity, their_identity) || DH(ephemeral, their_identity)
     *   - Derive shared secret via HKDF
     *
     * If we are the responder:
     *   - Compute: DH(our_identity, their_identity)
     *   - Derive shared secret via HKDF
     */
    async function establishSession(myPriv, myPub, theirPub, isInitiator) {
        // Step 1: Identity-to-Identity DH
        const dh1 = performDH(myPriv, theirPub);

        let combined;
        let ephemeralPublic = null;

        if (isInitiator) {
            // Step 2: Generate ephemeral key for forward secrecy
            const ephemeral = generateX25519KeyPair();
            ephemeralPublic = ephemeral.publicKey;
            const dh2 = performDH(ephemeral.privateKey, theirPub);

            // Combine both DH outputs
            combined = new Uint8Array(dh1.length + dh2.length);
            combined.set(dh1, 0);
            combined.set(dh2, dh1.length);
        } else {
            combined = dh1;
        }

        // Step 3: Derive root shared secret
        const { sorted, combined: saltBytes } = sortAndConcatKeys(myPub, theirPub);
        const sharedSecret = await deriveKey(
            combined,
            'comp3334_secure_im_session_v1',
            saltBytes
        );

        // Step 4: Derive directional chain keys
        let sendingChainKey, receivingChainKey;
        if (compareBytes(myPub, theirPub) <= 0) {
            // We are "party A" (lexicographically first)
            sendingChainKey = await deriveKey(sharedSecret, 'chain_a_to_b');
            receivingChainKey = await deriveKey(sharedSecret, 'chain_b_to_a');
        } else {
            // We are "party B"
            sendingChainKey = await deriveKey(sharedSecret, 'chain_b_to_a');
            receivingChainKey = await deriveKey(sharedSecret, 'chain_a_to_b');
        }

        return {
            sharedSecret,
            sendingChainKey,
            receivingChainKey,
            ephemeralPublic,
        };
    }

    /**
     * Complete session using the initiator's ephemeral key (responder side).
     * Called when we receive a message with an ephemeral key attached.
     */
    async function completeSessionWithEphemeral(myPriv, myPub, theirPub, theirEphemeralPub) {
        const dh1 = performDH(myPriv, theirPub);
        const dh2 = performDH(myPriv, theirEphemeralPub);

        const combined = new Uint8Array(dh1.length + dh2.length);
        combined.set(dh1, 0);
        combined.set(dh2, dh1.length);

        const { sorted, combined: saltBytes } = sortAndConcatKeys(myPub, theirPub);
        const sharedSecret = await deriveKey(
            combined,
            'comp3334_secure_im_session_v1',
            saltBytes
        );

        let sendingChainKey, receivingChainKey;
        if (compareBytes(myPub, theirPub) <= 0) {
            sendingChainKey = await deriveKey(sharedSecret, 'chain_a_to_b');
            receivingChainKey = await deriveKey(sharedSecret, 'chain_b_to_a');
        } else {
            sendingChainKey = await deriveKey(sharedSecret, 'chain_b_to_a');
            receivingChainKey = await deriveKey(sharedSecret, 'chain_a_to_b');
        }

        return { sharedSecret, sendingChainKey, receivingChainKey };
    }

    // ============================================================
    // Message Key Derivation (Symmetric Ratchet)
    // ============================================================

    /**
     * Derive a unique message key from chain key + counter.
     * Each message uses a different key (provides some forward secrecy).
     */
    async function deriveMessageKey(chainKey, counter) {
        // Pack counter as big-endian 8 bytes (matches Python struct.pack(">Q", counter))
        const counterBytes = new Uint8Array(8);
        const view = new DataView(counterBytes.buffer);
        view.setBigUint64(0, BigInt(counter), false); // big-endian

        // Build info: "message_key_" + counter bytes
        const prefix = new TextEncoder().encode('message_key_');
        const info = new Uint8Array(prefix.length + counterBytes.length);
        info.set(prefix, 0);
        info.set(counterBytes, prefix.length);

        return await deriveKey(chainKey, info);
    }

    // ============================================================
    // AES-256-GCM Encryption / Decryption
    // ============================================================

    /**
     * Encrypt a message using AES-256-GCM (authenticated encryption).
     * AES-GCM provides both confidentiality AND integrity.
     * The associated data (AD) is authenticated but not encrypted.
     *
     * @param {Uint8Array} messageKey - 32-byte AES key
     * @param {string} plaintext - Message text
     * @param {Uint8Array} associatedData - Metadata bound to ciphertext
     * @returns {Promise<{nonce: Uint8Array, ciphertext: Uint8Array}>}
     */
    async function encryptMessage(messageKey, plaintext, associatedData) {
        // Generate a random 12-byte nonce (must be unique per message+key)
        const nonce = crypto.getRandomValues(new Uint8Array(12));

        // Import the key into Web Crypto
        const key = await crypto.subtle.importKey(
            'raw', messageKey, { name: 'AES-GCM' }, false, ['encrypt']
        );

        // Encrypt with AES-256-GCM
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: associatedData },
            key,
            plaintextBytes
        );

        return { nonce, ciphertext: new Uint8Array(ciphertext) };
    }

    /**
     * Decrypt and verify a message using AES-256-GCM.
     * Throws if the ciphertext or associated data was tampered with.
     */
    async function decryptMessage(messageKey, nonce, ciphertext, associatedData) {
        const key = await crypto.subtle.importKey(
            'raw', messageKey, { name: 'AES-GCM' }, false, ['decrypt']
        );

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: associatedData },
            key,
            ciphertext
        );

        return new TextDecoder().decode(plaintext);
    }

    // ============================================================
    // Associated Data Construction
    // ============================================================

    /**
     * Build associated data that binds ciphertext to its context.
     * Format: "sender|receiver|counter|ttl"
     * This prevents message misrouting and TTL tampering.
     */
    function buildAssociatedData(sender, receiver, counter, ttl = null) {
        const ttlValue = ttl !== null ? ttl : 0;
        const adString = `${sender}|${receiver}|${counter}|${ttlValue}`;
        return new TextEncoder().encode(adString);
    }

    // ============================================================
    // Fingerprint / Safety Number (R5)
    // ============================================================

    /**
     * Compute a human-readable fingerprint for a conversation.
     * Both users will see the same fingerprint when they compare.
     * Uses SHA-256 of both sorted public keys.
     */
    async function computeFingerprint(pubKeyA, pubKeyB) {
        const { combined } = sortAndConcatKeys(pubKeyA, pubKeyB);
        const hash = await crypto.subtle.digest('SHA-256', combined);
        const bytes = new Uint8Array(hash);

        // Convert to groups of 5 digits (like Signal's safety numbers)
        const numbers = [];
        for (let i = 0; i < 30; i += 5) {
            const chunk = (bytes[i] << 32) | (bytes[i+1] << 24) |
                          (bytes[i+2] << 16) | (bytes[i+3] << 8) | bytes[i+4];
            // Use unsigned right shift to ensure non-negative
            const num = (chunk >>> 0) % 100000;
            numbers.push(String(num).padStart(5, '0'));
        }

        return numbers.join(' ');
    }

    // ============================================================
    // Local Key Storage Encryption
    // ============================================================

    /**
     * Derive a storage encryption key from the user's password.
     * Used to encrypt private keys before storing in localStorage.
     */
    async function deriveStorageKey(password, salt) {
        const passwordBytes = new TextEncoder().encode(password);
        return await deriveKey(passwordBytes, 'local_key_storage_v1', salt, 32);
    }

    /**
     * Encrypt a private key for secure local storage.
     * Returns an object with base64-encoded salt, nonce, and ciphertext.
     */
    async function encryptPrivateKey(password, keyBytes) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const storageKey = await deriveStorageKey(password, salt);
        const nonce = crypto.getRandomValues(new Uint8Array(12));

        const key = await crypto.subtle.importKey(
            'raw', storageKey, { name: 'AES-GCM' }, false, ['encrypt']
        );

        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode('private_key_storage') },
            key,
            keyBytes
        );

        return {
            salt: toBase64(salt),
            nonce: toBase64(nonce),
            ciphertext: toBase64(new Uint8Array(ciphertext)),
        };
    }

    /**
     * Decrypt a private key from local storage.
     * Throws if the password is wrong (AES-GCM tag verification fails).
     */
    async function decryptPrivateKey(password, encryptedData) {
        const salt = fromBase64(encryptedData.salt);
        const nonce = fromBase64(encryptedData.nonce);
        const ciphertext = fromBase64(encryptedData.ciphertext);

        const storageKey = await deriveStorageKey(password, salt);
        const key = await crypto.subtle.importKey(
            'raw', storageKey, { name: 'AES-GCM' }, false, ['decrypt']
        );

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode('private_key_storage') },
            key,
            ciphertext
        );

        return new Uint8Array(plaintext);
    }

    // ============================================================
    // Base64 encoding utilities
    // ============================================================

    /** Encode a Uint8Array to a base64 string. */
    function toBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /** Decode a base64 string to a Uint8Array. */
    function fromBase64(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // ============================================================
    // Public API
    // ============================================================

    return {
        generateX25519KeyPair,
        generateEd25519KeyPair,
        performDH,
        deriveKey,
        establishSession,
        completeSessionWithEphemeral,
        deriveMessageKey,
        encryptMessage,
        decryptMessage,
        buildAssociatedData,
        computeFingerprint,
        encryptPrivateKey,
        decryptPrivateKey,
        toBase64,
        fromBase64,
    };

})();
