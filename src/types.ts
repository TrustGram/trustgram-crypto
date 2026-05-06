// -------------------------
// Key types
// -------------------------

export interface KeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
}

export interface IdentityKeyBundle {
    identityKey: KeyPair
    signedPreKey: KeyPair
    oneTimePreKeys: KeyPair[]
}

// What gets published to server (public keys only)
export interface PublicKeyBundle {
    identityKey: string      // base64 raw public key
    signedPreKey: string     // base64 raw public key
    oneTimePreKeys: string[] // base64 raw public keys
}

// What server returns when Alice fetches Bob's keys
export interface RecipientKeyBundle {
    identityKey: string    // base64
    signedPreKey: string   // base64
    oneTimePreKey: string  // base64 (one, server removes it after)
}

// -------------------------
// X3DH
// -------------------------

export interface X3DHSenderBundle {
    identityKey: string    // base64 — Alices's IK pub (sent to Bob)
    ephemeralKey: string   // base64 — Alice's EK pub (sent to Bob)
    oneTimePreKeyId: string // which OPK was used
}

export interface X3DHResult {
    masterSecret: ArrayBuffer
    senderBundle: X3DHSenderBundle
}

// -------------------------
// Double Ratchet
// -------------------------

export interface RatchetState {
    // DH ratchet keys
    dhSendKey: KeyPair        // current sending DH key pair
    dhRecvKey: CryptoKey | null // last received DH public key

    // Chain keys (stored as raw bytes for HKDF)
    rootKey: ArrayBuffer
    sendChainKey: ArrayBuffer | null
    recvChainKey: ArrayBuffer | null

    // Message counters
    sendCount: number   // messages sent in current chain
    recvCount: number   // messages received in current chain
    prevSendCount: number // messages sent in previous chain

    // Skipped message keys (for out-of-order delivery)
    skippedKeys: SkippedKey[]
}

export interface SkippedKey {
    dhKey: string       // base64 public key
    n: number           // message number
    messageKey: ArrayBuffer
}

// -------------------------
// Messages
// -------------------------

export interface EncryptedMessage {
    dhPub: string      // base64 — sender's current DH public key
    n: number          // message number in current chain
    pn: number         // message count in previous chain
    iv: string         // base64
    ciphertext: string // base64
}

export interface DecryptedMessage {
    plaintext: string
    senderDhPub: string
}

// -------------------------
// Fingerprint
// -------------------------

export interface Fingerprint {
    hex: string
    display: string  // "1234 5678 9012 ..."
}
