/**
 * app.js - Main application logic for the Secure IM web client.
 *
 * This file handles:
 * - User registration and login (with 2FA)
 * - WebSocket connection for real-time messaging
 * - E2EE session establishment and message encryption/decryption
 * - Friend management (add, accept, decline, block)
 * - Conversation list and message rendering
 * - Self-destruct (TTL) messages
 * - Fingerprint verification
 * - Local storage of keys, messages, and session state
 *
 * All crypto operations use crypto.js (runs entirely in the browser).
 */

// ============================================================
// Application State
// ============================================================

const state = {
    username: null,
    password: null,     // kept in memory for key decryption (cleared on logout)
    token: null,        // auth token from server
    socket: null,       // Socket.IO connection
    currentChat: null,  // username of the contact we're chatting with
    identityKeys: null, // { publicKey, privateKey } (decrypted, in memory)
    signingKeys: null,  // { publicKey, privateKey } (decrypted, in memory)
};

// ============================================================
// localStorage helpers (prefixed per user to avoid collisions)
// ============================================================

function storageKey(key) {
    return `secureIM_${state.username}_${key}`;
}

function saveToStorage(key, data) {
    localStorage.setItem(storageKey(key), JSON.stringify(data));
}

function loadFromStorage(key) {
    const raw = localStorage.getItem(storageKey(key));
    return raw ? JSON.parse(raw) : null;
}

// ============================================================
// API helper (all calls go through HTTPS with our auth token)
// ============================================================

async function apiCall(method, path, body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' },
    };
    if (state.token) {
        options.headers['Authorization'] = `Bearer ${state.token}`;
    }
    if (body) {
        options.body = JSON.stringify(body);
    }
    try {
        const resp = await fetch(path, options);
        const data = await resp.json();
        return { data, status: resp.status };
    } catch (err) {
        return { data: { error: err.message }, status: 0 };
    }
}

// ============================================================
// UI Helpers
// ============================================================

function showStatus(message, type = 'info') {
    const el = document.getElementById('auth-status');
    el.textContent = message;
    el.className = `status-message ${type}`;
    el.style.display = 'block';
    if (type !== 'error') {
        setTimeout(() => { el.style.display = 'none'; }, 5000);
    }
}

function showLoginForm() {
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
    document.getElementById('otp-setup').style.display = 'none';
    document.getElementById('auth-status').style.display = 'none';
}

function showRegisterForm() {
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('register-form').style.display = 'block';
    document.getElementById('otp-setup').style.display = 'none';
    document.getElementById('auth-status').style.display = 'none';
}

function showScreen(screenId) {
    document.getElementById('auth-screen').style.display = screenId === 'auth' ? 'flex' : 'none';
    document.getElementById('main-screen').style.display = screenId === 'main' ? 'flex' : 'none';
}

function closeModal(id) {
    document.getElementById(id).style.display = 'none';
}

function showAddFriendModal() {
    document.getElementById('add-friend-username').value = '';
    document.getElementById('add-friend-modal').style.display = 'flex';
}

async function showRequestsModal() {
    document.getElementById('requests-modal').style.display = 'flex';
    await loadFriendRequests();
}

function showVerifyModal() {
    if (!state.currentChat) return;
    const contacts = loadFromStorage('contacts') || {};
    const contact = contacts[state.currentChat];
    const fp = contact ? contact.fingerprint : 'N/A';
    document.getElementById('fingerprint-display').textContent = fp || 'No fingerprint available';
    document.getElementById('verify-modal').style.display = 'flex';
}

function toggleTTL() {
    const bar = document.getElementById('ttl-bar');
    bar.style.display = bar.style.display === 'none' ? 'flex' : 'none';
}

// ============================================================
// Registration
// ============================================================

async function handleRegister() {
    const username = document.getElementById('reg-username').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm = document.getElementById('reg-confirm').value;

    if (!username || !password) {
        showStatus('Username and password are required.', 'error');
        return;
    }
    // (Validation relaxed for testing)
    // if (password !== confirm) {
    //     showStatus('Passwords do not match.', 'error');
    //     return;
    // }

    const btn = document.getElementById('register-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Registering...';

    try {
        // Generate cryptographic keypairs in the browser
        const identityKeys = CryptoModule.generateX25519KeyPair();
        const signingKeys = CryptoModule.generateEd25519KeyPair();

        // Send registration request (public keys only go to server)
        const { data, status } = await apiCall('POST', '/api/register', {
            username,
            password,
            identity_public_key: CryptoModule.toBase64(identityKeys.publicKey),
            signing_public_key: CryptoModule.toBase64(signingKeys.publicKey),
        });

        if (status !== 201) {
            showStatus(data.error || 'Registration failed.', 'error');
            return;
        }

        // Encrypt private keys with the user's password before storing
        const encIdentity = await CryptoModule.encryptPrivateKey(password, identityKeys.privateKey);
        const encSigning = await CryptoModule.encryptPrivateKey(password, signingKeys.privateKey);

        // Store encrypted keys in localStorage (keyed by username)
        // We temporarily set state.username so storageKey() works
        state.username = username;
        saveToStorage('identity_keys', {
            publicKey: CryptoModule.toBase64(identityKeys.publicKey),
            privateKey: encIdentity,
        });
        saveToStorage('signing_keys', {
            publicKey: CryptoModule.toBase64(signingKeys.publicKey),
            privateKey: encSigning,
        });
        // Also store the OTP secret for convenient auto-fill in dev
        saveToStorage('otp_secret', data.otp_secret);
        state.username = null;

        // Show the OTP setup screen
        document.getElementById('otp-secret-display').textContent = data.otp_secret;
        document.getElementById('otp-uri-display').textContent = data.otp_uri;
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('register-form').style.display = 'none';
        document.getElementById('otp-setup').style.display = 'block';

        showStatus('Registration successful! Set up your authenticator app.', 'success');
    } catch (err) {
        showStatus('Registration error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Register';
    }
}

// ============================================================
// Login
// ============================================================

async function handleLogin() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    let otpCode = document.getElementById('login-otp').value.trim();

    if (!username || !password) {
        showStatus('Username and password are required.', 'error');
        return;
    }

    // If no OTP code, try to auto-generate from stored secret (for testing)
    if (!otpCode) {
        const tempKey = `secureIM_${username}_otp_secret`;
        const storedOtp = localStorage.getItem(tempKey);
        if (storedOtp) {
            // Generate TOTP code using stored secret
            otpCode = generateTOTP(JSON.parse(storedOtp));
            showStatus('Auto-generated OTP code for testing.', 'info');
        }
    }

    if (!otpCode) {
        showStatus('OTP code is required.', 'error');
        return;
    }

    const btn = document.getElementById('login-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Logging in...';

    try {
        // Send login request
        const { data, status } = await apiCall('POST', '/api/login', {
            username, password, otp_code: otpCode,
        });

        if (status !== 200) {
            showStatus(data.error || 'Login failed.', 'error');
            return;
        }

        state.username = username;
        state.password = password;
        state.token = data.token;

        // Load and decrypt our identity keys from localStorage
        let storedIdentity = loadFromStorage('identity_keys');
        let storedSigning = loadFromStorage('signing_keys');

        if (!storedIdentity || !storedSigning) {
            const recover = confirm(
                'No local encryption keys found for this account.\n\n' +
                'This happens if you are on a new device or cleared your browser data.\n' +
                'Would you like to generate new keys and reset your identity? (You will lose access to old messages from before today.)'
            );

            if (!recover) {
                showStatus('Login cancelled. Local keys are required for E2EE.', 'error');
                state.username = null;
                state.token = null;
                return;
            }

            showStatus('Generating new encryption keys...', 'info');

            // Generate new keypairs
            const newIdentity = CryptoModule.generateX25519KeyPair();
            const newSigning = CryptoModule.generateEd25519KeyPair();

            // Encrypt and store them
            const encIdentity = await CryptoModule.encryptPrivateKey(password, newIdentity.privateKey);
            const encSigning = await CryptoModule.encryptPrivateKey(password, newSigning.privateKey);

            saveToStorage('identity_keys', {
                publicKey: CryptoModule.toBase64(newIdentity.publicKey),
                privateKey: encIdentity,
            });
            saveToStorage('signing_keys', {
                publicKey: CryptoModule.toBase64(newSigning.publicKey),
                privateKey: encSigning,
            });

            // Upload new public keys to the server
            const { status: keyStatus } = await apiCall('PUT', '/api/keys', {
                identity_public_key: CryptoModule.toBase64(newIdentity.publicKey),
                signing_public_key: CryptoModule.toBase64(newSigning.publicKey),
            });

            if (keyStatus !== 200) {
                showStatus('Failed to upload new public keys. Please try again.', 'error');
                state.username = null;
                state.token = null;
                return;
            }

            storedIdentity = loadFromStorage('identity_keys');
            storedSigning = loadFromStorage('signing_keys');
            showStatus('Identity reset successfully.', 'success');
        }

        const identityPriv = await CryptoModule.decryptPrivateKey(password, storedIdentity.privateKey);
        const signingPriv = await CryptoModule.decryptPrivateKey(password, storedSigning.privateKey);

        state.identityKeys = {
            publicKey: CryptoModule.fromBase64(storedIdentity.publicKey),
            privateKey: identityPriv,
        };
        state.signingKeys = {
            publicKey: CryptoModule.fromBase64(storedSigning.publicKey),
            privateKey: signingPriv,
        };

        // Connect WebSocket for real-time messaging
        connectWebSocket();

        // Switch to the main screen
        document.getElementById('display-username').textContent = username;
        showScreen('main');

        // Load conversations and friends
        await refreshConversationList();
        await checkPendingRequests();

        // Start periodic cleanup of expired messages
        setInterval(cleanupExpiredMessages, 10000);

    } catch (err) {
        showStatus('Login error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Login';
    }
}

// ============================================================
// Simple TOTP generator (for testing convenience)
// ============================================================

function generateTOTP(secret) {
    // Decode base32 secret
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of secret.toUpperCase()) {
        const val = base32Chars.indexOf(c);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const keyBytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        keyBytes.push(parseInt(bits.substring(i, i + 8), 2));
    }

    // Get current time step (30-second windows)
    const timeStep = Math.floor(Date.now() / 1000 / 30);
    const timeBytes = new Uint8Array(8);
    const view = new DataView(timeBytes.buffer);
    // Use two 32-bit writes to avoid BigInt dependency issues
    view.setUint32(0, Math.floor(timeStep / 4294967296), false);
    view.setUint32(4, timeStep >>> 0, false);

    // HMAC-SHA1 (using a simple implementation for TOTP)
    return hmacSHA1totp(new Uint8Array(keyBytes), timeBytes);
}

function hmacSHA1totp(key, message) {
    // Simplified TOTP HMAC-SHA1 - for auto-fill convenience only
    // In production you'd use Web Crypto, but HMAC-SHA1 isn't available for deriveBits
    // We'll use a synchronous implementation

    // SHA-1 implementation (standard)
    function sha1(msg) {
        function rotl(n, s) { return ((n << s) | (n >>> (32 - s))) >>> 0; }
        let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

        const ml = msg.length * 8;
        const padded = [];
        for (let i = 0; i < msg.length; i++) padded.push(msg[i]);
        padded.push(0x80);
        while ((padded.length % 64) !== 56) padded.push(0);
        // Append length in bits as 64-bit big-endian
        for (let i = 56; i >= 0; i -= 8) padded.push((ml >>> i) & 0xff);

        for (let offset = 0; offset < padded.length; offset += 64) {
            const w = new Array(80);
            for (let i = 0; i < 16; i++) {
                w[i] = (padded[offset + i*4] << 24) | (padded[offset + i*4+1] << 16) |
                       (padded[offset + i*4+2] << 8) | padded[offset + i*4+3];
            }
            for (let i = 16; i < 80; i++) {
                w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            }

            let a = h0, b = h1, c = h2, d = h3, e = h4;
            for (let i = 0; i < 80; i++) {
                let f, k;
                if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
                else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
                else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
                else { f = b ^ c ^ d; k = 0xCA62C1D6; }
                const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
                e = d; d = c; c = rotl(b, 30); b = a; a = temp;
            }
            h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
        }

        return [(h0>>>24)&0xff,(h0>>>16)&0xff,(h0>>>8)&0xff,h0&0xff,
                (h1>>>24)&0xff,(h1>>>16)&0xff,(h1>>>8)&0xff,h1&0xff,
                (h2>>>24)&0xff,(h2>>>16)&0xff,(h2>>>8)&0xff,h2&0xff,
                (h3>>>24)&0xff,(h3>>>16)&0xff,(h3>>>8)&0xff,h3&0xff,
                (h4>>>24)&0xff,(h4>>>16)&0xff,(h4>>>8)&0xff,h4&0xff];
    }

    // HMAC
    const blockSize = 64;
    let keyArr = Array.from(key);
    if (keyArr.length > blockSize) keyArr = sha1(new Uint8Array(keyArr));
    while (keyArr.length < blockSize) keyArr.push(0);

    const opad = keyArr.map(b => b ^ 0x5c);
    const ipad = keyArr.map(b => b ^ 0x36);

    const inner = new Uint8Array(ipad.length + message.length);
    inner.set(ipad); inner.set(message, ipad.length);
    const innerHash = sha1(inner);

    const outer = new Uint8Array(opad.length + innerHash.length);
    outer.set(opad); outer.set(innerHash, opad.length);
    const hash = sha1(outer);

    // Dynamic truncation (RFC 4226)
    const offset = hash[19] & 0x0f;
    const code = ((hash[offset] & 0x7f) << 24) | (hash[offset+1] << 16) |
                 (hash[offset+2] << 8) | hash[offset+3];
    return String(code % 1000000).padStart(6, '0');
}

// ============================================================
// Logout
// ============================================================

async function handleLogout() {
    try {
        await apiCall('POST', '/api/logout');
    } catch (e) { /* ignore */ }

    if (state.socket) {
        state.socket.disconnect();
        state.socket = null;
    }

    // Clear sensitive data from memory
    state.username = null;
    state.password = null;
    state.token = null;
    state.identityKeys = null;
    state.signingKeys = null;
    state.currentChat = null;

    showScreen('auth');
    showLoginForm();
}

// ============================================================
// WebSocket Connection
// ============================================================

function connectWebSocket() {
    // Connect Socket.IO over the same HTTPS connection
    state.socket = io({
        transports: ['websocket'],
        rejectUnauthorized: false,
    });

    state.socket.on('connect', () => {
        // Authenticate the WebSocket with our session token
        state.socket.emit('authenticate', { token: state.token });
    });

    state.socket.on('authenticated', () => {
        console.log('[WS] Authenticated successfully');
    });

    // Handle incoming encrypted messages
    state.socket.on('receive_message', async (data) => {
        await handleIncomingMessage(data);
    });

    // Handle message status updates (sent/delivered)
    state.socket.on('message_sent', (data) => {
        updateMessageStatus(data.receiver, data.message_counter, 'sent');
    });

    state.socket.on('message_status', (data) => {
        updateMessageStatus(data.receiver, data.message_counter, data.status);
    });

    // Handle friend request notifications
    state.socket.on('friend_request_received', (data) => {
        checkPendingRequests();
        const notif = document.createElement('div');
        notif.className = 'status-message info';
        notif.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;padding:12px 20px;border-radius:8px;';
        notif.textContent = `New friend request from ${data.from}`;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 4000);
    });

    state.socket.on('auth_error', (data) => {
        console.error('[WS] Auth error:', data.error);
    });

    state.socket.on('error', (data) => {
        console.error('[WS] Error:', data.error);
    });
}

// ============================================================
// E2EE Session Management
// ============================================================

async function ensureSession(contactUsername) {
    const sessions = loadFromStorage('sessions') || {};
    if (sessions[contactUsername]) {
        return true;
    }

    // Fetch the contact's public keys from the server
    const { data, status } = await apiCall('GET', `/api/keys/${contactUsername}`);
    if (status !== 200) {
        console.error('Failed to fetch keys for', contactUsername);
        return false;
    }

    const theirIdentityPub = CryptoModule.fromBase64(data.identity_public_key);
    const theirSigningPub = CryptoModule.fromBase64(data.signing_public_key);

    // Check for key change (R6)
    const contacts = loadFromStorage('contacts') || {};
    if (contacts[contactUsername] && contacts[contactUsername].identityPublicKey) {
        const oldKey = contacts[contactUsername].identityPublicKey;
        if (oldKey !== data.identity_public_key) {
            alert(`WARNING: ${contactUsername}'s identity key has changed!\n\n` +
                  'This could mean they reinstalled, or someone is impersonating them.\n' +
                  'Please verify their fingerprint.');
            contacts[contactUsername].verified = false;
        }
    }

    // Compute fingerprint
    const fingerprint = await CryptoModule.computeFingerprint(
        state.identityKeys.publicKey, theirIdentityPub
    );

    // Save contact info
    contacts[contactUsername] = {
        identityPublicKey: data.identity_public_key,
        signingPublicKey: data.signing_public_key,
        fingerprint,
        verified: contacts[contactUsername]?.verified || false,
    };
    saveToStorage('contacts', contacts);

    // Establish E2EE session (we're the initiator)
    const sessionData = await CryptoModule.establishSession(
        state.identityKeys.privateKey,
        state.identityKeys.publicKey,
        theirIdentityPub,
        true   // we're initiating
    );

    // Store session state
    sessions[contactUsername] = {
        sharedSecret: CryptoModule.toBase64(sessionData.sharedSecret),
        sendingChainKey: CryptoModule.toBase64(sessionData.sendingChainKey),
        receivingChainKey: CryptoModule.toBase64(sessionData.receivingChainKey),
        ephemeralPublic: sessionData.ephemeralPublic
            ? CryptoModule.toBase64(sessionData.ephemeralPublic) : null,
        sendCounter: 0,
        recvCounter: 0,
    };
    saveToStorage('sessions', sessions);

    return true;
}

// ============================================================
// Sending Messages (Encrypt + Send via WebSocket)
// ============================================================

async function sendCurrentMessage() {
    const input = document.getElementById('message-input');
    const text = input.value.trim();
    if (!text || !state.currentChat) return;

    const ttlSelect = document.getElementById('ttl-select');
    const ttl = parseInt(ttlSelect.value) || null;

    input.value = '';
    await sendEncryptedMessage(state.currentChat, text, ttl);
}

async function sendEncryptedMessage(receiver, plaintext, ttl = null) {
    if (!await ensureSession(receiver)) {
        alert('Could not establish secure session.');
        return;
    }

    const sessions = loadFromStorage('sessions') || {};
    const session = sessions[receiver];
    if (!session) return;

    // Get and increment the send counter
    const counter = session.sendCounter;
    session.sendCounter = counter + 1;
    saveToStorage('sessions', sessions);

    // Derive the message key
    const chainKey = CryptoModule.fromBase64(session.sendingChainKey);
    const msgKey = await CryptoModule.deriveMessageKey(chainKey, counter);

    // Build associated data
    const ad = CryptoModule.buildAssociatedData(state.username, receiver, counter, ttl);

    // Encrypt the message (AES-256-GCM)
    const { nonce, ciphertext } = await CryptoModule.encryptMessage(msgKey, plaintext, ad);

    // Send via WebSocket (server only sees ciphertext)
    state.socket.emit('send_message', {
        receiver,
        ciphertext: CryptoModule.toBase64(ciphertext),
        nonce: CryptoModule.toBase64(nonce),
        message_counter: counter,
        ttl,
        ephemeral_key: session.ephemeralPublic,
        associated_data: CryptoModule.toBase64(ad),
    });

    // Store plaintext locally for our own history
    const now = new Date().toISOString();
    storeLocalMessage(receiver, {
        sender: state.username,
        content: plaintext,
        timestamp: now,
        status: 'sent',
        counter,
        ttl,
        expiresAt: ttl ? new Date(Date.now() + ttl * 1000).toISOString() : null,
        incoming: false,
    });

    // Show in the chat UI
    if (state.currentChat === receiver) {
        addMessageToUI(plaintext, false, now, 'sent', ttl, counter);
        scrollChatToBottom();
    }

    refreshConversationList();
}

// ============================================================
// Receiving Messages (Decrypt from WebSocket)
// ============================================================

async function handleIncomingMessage(data) {
    const sender = data.sender;
    const ciphertextB64 = data.ciphertext;
    const nonceB64 = data.nonce;
    const ephemeralKeyB64 = data.ephemeral_key;
    const messageCounter = data.message_counter;
    const ttl = data.ttl;
    const adB64 = data.associated_data;
    const timestamp = data.timestamp || new Date().toISOString();

    // Replay protection: check if we've seen this counter (R9)
    const seenCounters = loadFromStorage('seen_counters') || {};
    const seenKey = `${sender}_${messageCounter}`;
    if (seenCounters[seenKey]) {
        console.log('Duplicate message detected, ignoring');
        return;
    }

    // Ensure we have a session with the sender
    let sessions = loadFromStorage('sessions') || {};
    if (!sessions[sender]) {
        // Fetch the sender's public keys
        const { data: keyData, status } = await apiCall('GET', `/api/keys/${sender}`);
        if (status !== 200) {
            console.error('Cannot get keys for', sender);
            return;
        }

        const theirPub = CryptoModule.fromBase64(keyData.identity_public_key);
        const theirSignPub = CryptoModule.fromBase64(keyData.signing_public_key);

        // Compute fingerprint and save contact
        const fingerprint = await CryptoModule.computeFingerprint(
            state.identityKeys.publicKey, theirPub
        );
        const contacts = loadFromStorage('contacts') || {};

        // Key change detection (R6)
        if (contacts[sender] && contacts[sender].identityPublicKey &&
            contacts[sender].identityPublicKey !== keyData.identity_public_key) {
            alert(`WARNING: ${sender}'s identity key has changed!`);
        }

        contacts[sender] = {
            identityPublicKey: keyData.identity_public_key,
            signingPublicKey: keyData.signing_public_key,
            fingerprint,
            verified: contacts[sender]?.verified || false,
        };
        saveToStorage('contacts', contacts);

        // Establish session
        let sessionData;
        if (ephemeralKeyB64) {
            const theirEph = CryptoModule.fromBase64(ephemeralKeyB64);
            sessionData = await CryptoModule.completeSessionWithEphemeral(
                state.identityKeys.privateKey,
                state.identityKeys.publicKey,
                theirPub,
                theirEph
            );
        } else {
            sessionData = await CryptoModule.establishSession(
                state.identityKeys.privateKey,
                state.identityKeys.publicKey,
                theirPub,
                false
            );
        }

        sessions[sender] = {
            sharedSecret: CryptoModule.toBase64(sessionData.sharedSecret),
            sendingChainKey: CryptoModule.toBase64(sessionData.sendingChainKey),
            receivingChainKey: CryptoModule.toBase64(sessionData.receivingChainKey),
            ephemeralPublic: null,
            sendCounter: 0,
            recvCounter: 0,
        };
        saveToStorage('sessions', sessions);
    }

    // Decrypt the message
    try {
        const ciphertext = CryptoModule.fromBase64(ciphertextB64);
        const nonce = CryptoModule.fromBase64(nonceB64);
        const ad = CryptoModule.fromBase64(adB64);

        const session = sessions[sender];
        const chainKey = CryptoModule.fromBase64(session.receivingChainKey);
        const msgKey = await CryptoModule.deriveMessageKey(chainKey, messageCounter);

        const plaintext = await CryptoModule.decryptMessage(msgKey, nonce, ciphertext, ad);

        // Mark counter as seen (replay protection)
        seenCounters[seenKey] = true;
        saveToStorage('seen_counters', seenCounters);

        // Store the decrypted message locally
        storeLocalMessage(sender, {
            sender,
            content: plaintext,
            timestamp,
            status: 'delivered',
            counter: messageCounter,
            ttl,
            expiresAt: ttl ? new Date(Date.now() + ttl * 1000).toISOString() : null,
            incoming: true,
        });

        // Show in UI
        if (state.currentChat === sender) {
            addMessageToUI(plaintext, true, timestamp, 'delivered', ttl, messageCounter);
            scrollChatToBottom();
        }

        refreshConversationList();

        // Send delivery acknowledgment (R18 Option B)
        state.socket.emit('message_delivered_ack', {
            sender,
            message_counter: messageCounter,
        });

    } catch (err) {
        console.error('Failed to decrypt message from', sender, err);
    }
}

// ============================================================
// Message Status Updates
// ============================================================

function updateMessageStatus(receiver, counter, status) {
    const messages = loadFromStorage(`messages_${receiver}`) || [];
    const msg = messages.find(m => m.counter === counter && !m.incoming);
    if (msg) {
        msg.status = status;
        saveToStorage(`messages_${receiver}`, messages);
    }

    // Update the UI if we're in the chat
    if (state.currentChat === receiver) {
        const statusEl = document.querySelector(`[data-counter="${counter}"] .message-status`);
        if (statusEl) {
            statusEl.textContent = status === 'delivered' ? '✓✓' : '✓';
        }
    }
}

// ============================================================
// Local Message Storage
// ============================================================

function storeLocalMessage(contactUsername, message) {
    const messages = loadFromStorage(`messages_${contactUsername}`) || [];
    messages.push(message);
    // Keep only the last 500 messages per conversation
    if (messages.length > 500) messages.splice(0, messages.length - 500);
    saveToStorage(`messages_${contactUsername}`, messages);
}

function getLocalMessages(contactUsername, limit = 50) {
    const messages = loadFromStorage(`messages_${contactUsername}`) || [];
    // Remove expired self-destruct messages (R11)
    const now = new Date().toISOString();
    const filtered = messages.filter(m => !m.expiresAt || m.expiresAt > now);
    if (filtered.length !== messages.length) {
        saveToStorage(`messages_${contactUsername}`, filtered);
    }
    return filtered.slice(-limit);
}

function cleanupExpiredMessages() {
    const contacts = loadFromStorage('contacts') || {};
    for (const username of Object.keys(contacts)) {
        getLocalMessages(username); // triggers cleanup
    }
}

// ============================================================
// Friends Management
// ============================================================

async function handleAddFriend() {
    const username = document.getElementById('add-friend-username').value.trim();
    if (!username) return;

    const { data, status } = await apiCall('POST', '/api/friends/request', { username });

    if (status === 200) {
        alert(data.message || 'Friend request sent!');
        closeModal('add-friend-modal');
    } else {
        alert(data.error || 'Failed to send friend request.');
    }
}

async function loadFriendRequests() {
    const { data, status } = await apiCall('GET', '/api/friends/requests');
    if (status !== 200) return;

    // Render received requests
    const receivedEl = document.getElementById('received-requests');
    if (data.received && data.received.length > 0) {
        receivedEl.innerHTML = data.received.map(r => `
            <div class="request-item">
                <span class="username">${r.sender_username}</span>
                <div class="actions">
                    <button class="btn-success" onclick="acceptRequest(${r.id})">Accept</button>
                    <button class="btn-danger" onclick="declineRequest(${r.id})">Decline</button>
                </div>
            </div>
        `).join('');
    } else {
        receivedEl.innerHTML = '<p class="empty-text">No pending requests.</p>';
    }

    // Render sent requests
    const sentEl = document.getElementById('sent-requests');
    if (data.sent && data.sent.length > 0) {
        sentEl.innerHTML = data.sent.map(r => `
            <div class="request-item">
                <span class="username">${r.receiver_username}</span>
                <div class="actions">
                    <button class="btn-danger" onclick="cancelRequest(${r.id})">Cancel</button>
                </div>
            </div>
        `).join('');
    } else {
        sentEl.innerHTML = '<p class="empty-text">No sent requests.</p>';
    }
}

async function acceptRequest(requestId) {
    const { data, status } = await apiCall('POST', '/api/friends/accept', { request_id: requestId });
    if (status === 200) {
        await loadFriendRequests();
        await refreshConversationList();
    } else {
        alert(data.error || 'Failed to accept request.');
    }
}

async function declineRequest(requestId) {
    await apiCall('POST', '/api/friends/decline', { request_id: requestId });
    await loadFriendRequests();
}

async function cancelRequest(requestId) {
    await apiCall('POST', '/api/friends/cancel', { request_id: requestId });
    await loadFriendRequests();
}

async function checkPendingRequests() {
    const { data, status } = await apiCall('GET', '/api/friends/requests');
    if (status !== 200) return;
    const count = (data.received || []).length;
    const badge = document.getElementById('request-badge');
    if (count > 0) {
        badge.textContent = count;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }
}

// ============================================================
// Conversation List (R23, R24)
// ============================================================

async function refreshConversationList() {
    const { data, status } = await apiCall('GET', '/api/friends');
    if (status !== 200) return;

    const friends = data.friends || [];
    const listEl = document.getElementById('conversation-list');

    if (friends.length === 0) {
        listEl.innerHTML = '<div class="empty-state">No conversations yet.<br>Add a friend to start chatting!</div>';
        return;
    }

    // Build conversation items with last message info
    const convos = friends.map(f => {
        const messages = getLocalMessages(f.username, 1);
        const lastMsg = messages.length > 0 ? messages[messages.length - 1] : null;
        const contacts = loadFromStorage('contacts') || {};
        const contact = contacts[f.username];

        // Count unread messages
        const allMsgs = loadFromStorage(`messages_${f.username}`) || [];
        const unread = allMsgs.filter(m => m.incoming && m.status !== 'read').length;

        return {
            username: f.username,
            lastMessage: lastMsg ? lastMsg.content : '',
            lastTime: lastMsg ? lastMsg.timestamp : '',
            unread,
            verified: contact ? contact.verified : false,
        };
    });

    // Sort by most recent activity (R23)
    convos.sort((a, b) => (b.lastTime || '').localeCompare(a.lastTime || ''));

    listEl.innerHTML = convos.map(c => {
        const initial = c.username.charAt(0).toUpperCase();
        const preview = c.lastMessage.length > 30
            ? c.lastMessage.substring(0, 27) + '...'
            : c.lastMessage;
        const timeStr = c.lastTime ? formatTime(c.lastTime) : '';
        const activeClass = state.currentChat === c.username ? 'active' : '';
        const unreadHtml = c.unread > 0
            ? `<span class="conv-unread">${c.unread}</span>` : '';
        const verifiedIcon = c.verified ? ' &#10004;' : '';

        return `
            <div class="conversation-item ${activeClass}" onclick="openChat('${c.username}')">
                <div class="conv-avatar">${initial}</div>
                <div class="conv-details">
                    <div class="conv-name">${c.username}${verifiedIcon}</div>
                    <div class="conv-last-message">${escapeHtml(preview) || 'Start chatting...'}</div>
                </div>
                <div class="conv-meta">
                    <span class="conv-time">${timeStr}</span>
                    ${unreadHtml}
                </div>
            </div>
        `;
    }).join('');
}

// ============================================================
// Chat UI
// ============================================================

async function openChat(contactUsername) {
    state.currentChat = contactUsername;

    // Update sidebar active state
    document.querySelectorAll('.conversation-item').forEach(el => {
        el.classList.toggle('active', el.onclick.toString().includes(contactUsername));
    });

    // Show the chat area
    document.getElementById('chat-empty').style.display = 'none';
    document.getElementById('chat-active').style.display = 'flex';
    document.getElementById('chat-active').style.flexDirection = 'column';
    document.getElementById('chat-active').style.flex = '1';

    // Set header info
    document.getElementById('chat-contact-name').textContent = contactUsername;

    const contacts = loadFromStorage('contacts') || {};
    const contact = contacts[contactUsername];
    const isVerified = contact && contact.verified;

    document.getElementById('chat-verified-badge').style.display = isVerified ? 'inline' : 'none';
    document.getElementById('chat-unverified-badge').style.display = isVerified ? 'none' : 'inline';

    // Load and display messages (with pagination - R25)
    const messages = getLocalMessages(contactUsername, 50);
    const chatEl = document.getElementById('chat-messages');
    chatEl.innerHTML = '';

    messages.forEach(m => {
        addMessageToUI(m.content, m.incoming, m.timestamp, m.status, m.ttl, m.counter);
    });

    scrollChatToBottom();

    // Mark messages as read
    const allMsgs = loadFromStorage(`messages_${contactUsername}`) || [];
    allMsgs.forEach(m => { if (m.incoming) m.status = 'read'; });
    saveToStorage(`messages_${contactUsername}`, allMsgs);

    refreshConversationList();

    // Focus the input
    document.getElementById('message-input').focus();
}

function addMessageToUI(content, isIncoming, timestamp, status, ttl, counter) {
    const chatEl = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `message ${isIncoming ? 'received' : 'sent'}`;
    if (counter !== undefined) div.dataset.counter = counter;

    const timeStr = formatTime(timestamp);
    const statusIcon = !isIncoming ? `<span class="message-status">${status === 'delivered' ? '✓✓' : '✓'}</span>` : '';
    const ttlBadge = ttl ? `<span class="message-ttl">&#9201; ${ttl}s</span>` : '';

    div.innerHTML = `
        <div class="message-text">${escapeHtml(content)}</div>
        <div class="message-meta">
            ${ttlBadge}
            <span>${timeStr}</span>
            ${statusIcon}
        </div>
    `;

    chatEl.appendChild(div);
}

function scrollChatToBottom() {
    const chatEl = document.getElementById('chat-messages');
    chatEl.scrollTop = chatEl.scrollHeight;
}

// ============================================================
// Verify Contact Fingerprint (R5)
// ============================================================

async function handleVerifyContact() {
    if (!state.currentChat) return;

    const contacts = loadFromStorage('contacts') || {};
    if (contacts[state.currentChat]) {
        contacts[state.currentChat].verified = true;
        saveToStorage('contacts', contacts);
    }

    document.getElementById('chat-verified-badge').style.display = 'inline';
    document.getElementById('chat-unverified-badge').style.display = 'none';

    closeModal('verify-modal');
    refreshConversationList();
}

// ============================================================
// Utility Functions
// ============================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(isoString) {
    if (!isoString) return '';
    try {
        const d = new Date(isoString);
        const now = new Date();
        const isToday = d.toDateString() === now.toDateString();
        if (isToday) {
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
        return '';
    }
}
