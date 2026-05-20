// -------------------------
// Key types
// -------------------------

/** An ECDH P-256 key pair. Private key is non-extractable (stays in WebCrypto). */
export interface KeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
}

/** Full identity stored locally: IK + signingKey + SPK + 10 OPKs (all with private keys). */
export interface IdentityKeyBundle {
    identityKey: KeyPair        // ECDH P-256 — used for X3DH
    signingKey: KeyPair         // ECDSA P-256 — used to sign SPK + as trust anchor
    signedPreKey: KeyPair
    oneTimePreKeys: KeyPair[]
}

/** Public-only projection of IdentityKeyBundle — safe to publish to server. */
export interface PublicKeyBundle {
    identityKey: string             // base64 raw ECDH public key
    signingKey: string              // base64 SPKI ECDSA public key
    signedPreKey: string            // base64 raw public key
    signedPreKeySignature: string   // base64 ECDSA(signingKey, signedPreKey)
    oneTimePreKeys: string[]        // base64 raw public keys
}

/** Server response when Alice fetches Bob's keys. Server removes the OPK after delivery. */
export interface RecipientKeyBundle {
    identityKey: string             // base64 ECDH
    signingKey: string              // base64 SPKI ECDSA
    signedPreKey: string            // base64
    signedPreKeySignature: string   // base64 ECDSA signature over signedPreKey
    oneTimePreKey: string | null    // base64, or null if pool is exhausted
}

// -------------------------
// X3DH
// -------------------------

/** What Alice sends to Bob so he can reproduce the X3DH master secret. */
export interface X3DHSenderBundle {
    identityKey: string          // base64 — Alice's IK pub
    ephemeralKey: string         // base64 — Alice's EK pub
    oneTimePreKeyId: string | null  // OPK used, or null if no OPK was available
}

export interface X3DHResult {
    masterSecret: ArrayBuffer
    senderBundle: X3DHSenderBundle
}

// -------------------------
// Double Ratchet
// -------------------------

/**
 * Mutable ratchet state passed in/out of every encrypt and decrypt call.
 * Never mutated in place — each operation returns a new state object.
 */
export interface RatchetState {
    // DH ratchet keys
    dhSendKey: KeyPair          // current sending DH key pair
    dhRecvKey: CryptoKey | null // last received DH public key (null before first message)

    // Chain keys (raw bytes for HKDF input)
    rootKey: ArrayBuffer
    sendChainKey: ArrayBuffer | null
    recvChainKey: ArrayBuffer | null

    // Message counters
    sendCount: number      // messages sent in current chain
    recvCount: number      // messages received in current chain
    prevSendCount: number  // messages sent in previous sending chain (written into pn header)

    // Stored keys for out-of-order delivery
    skippedKeys: SkippedKey[]
}

/** A pre-derived message key saved when a later message arrives before an earlier one. */
export interface SkippedKey {
    dhKey: string        // base64 sender DH public key (identifies the chain)
    n: number            // message number within that chain
    messageKey: ArrayBuffer
}

// -------------------------
// Messages
// -------------------------

/**
 * Wire format for an encrypted message.
 * All fields are base64 strings or numbers — safe to JSON-serialize.
 */
export interface EncryptedMessage {
    dhPub: string      // base64 — sender's current DH public key
    n: number          // message number in current chain
    pn: number         // message count in previous chain (used to skip keys on DH ratchet)
    iv: string         // base64 — AES-GCM nonce
    ciphertext: string // base64 — AES-256-GCM output including auth tag
}

export interface DecryptedMessage {
    plaintext: string
    senderDhPub: string
}

// -------------------------
// Fingerprint
// -------------------------

/**
 * Safety number derived from both parties' identity keys.
 * Both sides compute the same value — users compare out-of-band to detect MITM.
 */
export interface Fingerprint {
    hex: string      // full 64-char hex string
    display: string  // grouped for readability: "1234 5678 9012 ..."
}
