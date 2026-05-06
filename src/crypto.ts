// TrustGram Crypto Engine
// All cryptographic operations use the browser's built-in Web Crypto API.
// Zero external dependencies.

// -------------------------
// Types
// -------------------------

export interface KeyPair {
    privateKey: CryptoKey
    publicKey: CryptoKey
}

export interface EncryptedMessage {
    iv: string        // base64
    ciphertext: string // base64
}

export interface Fingerprint {
    hex: string   // full SHA-256 hex
    display: string // "1234 5678 9012 ..."
}

// -------------------------
// Encoding helpers
// -------------------------

function toBase64(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
}

function fromBase64(b64: string): ArrayBuffer {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer
}

// -------------------------
// Key generation
// -------------------------

export async function generateKeyPair(): Promise<KeyPair> {
    return crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"]
    ) as Promise<KeyPair>
}

// -------------------------
// Key export / import
// -------------------------

export async function exportPublicKey(key: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey("raw", key)
    return toBase64(raw)
}

export async function importPublicKey(b64: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        fromBase64(b64),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    )
}

// -------------------------
// Key derivation
// -------------------------

export async function deriveAESKey(privateKey: CryptoKey, theirPublicKey: CryptoKey): Promise<CryptoKey> {
    const shared = await crypto.subtle.deriveKey(
        { name: "ECDH", public: theirPublicKey },
        privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    )
    return shared
}

// -------------------------
// Encryption / Decryption
// -------------------------

export async function encrypt(key: CryptoKey, plaintext: string): Promise<EncryptedMessage> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encoded = new TextEncoder().encode(plaintext)
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoded
    )
    return {
        iv: toBase64(iv.buffer),
        ciphertext: toBase64(ciphertext)
    }
}

export async function decrypt(key: CryptoKey, iv: string, ciphertext: string): Promise<string> {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(iv) },
        key,
        fromBase64(ciphertext)
    )
    return new TextDecoder().decode(decrypted)
}

// -------------------------
// Fingerprint (Safety Numbers)
// -------------------------

export async function computeFingerprint(myPublicKey: CryptoKey, theirPublicKey: CryptoKey): Promise<Fingerprint> {
    const myRaw = await crypto.subtle.exportKey("raw", myPublicKey)
    const theirRaw = await crypto.subtle.exportKey("raw", theirPublicKey)

    // Sort so both sides get the same result regardless of who calls first
    const myArr = new Uint8Array(myRaw)
    const theirArr = new Uint8Array(theirRaw)
    const combined = myArr[0] < theirArr[0]
        ? new Uint8Array([...myArr, ...theirArr])
        : new Uint8Array([...theirArr, ...myArr])

    const hash = await crypto.subtle.digest("SHA-256", combined)
    const hex = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")

    // Format as groups of 4 digits for easy comparison
    const display = hex.match(/.{1,4}/g)!.join(" ")

    return { hex, display }
}

// -------------------------
// Public API
// -------------------------

const TrustGramCrypto = {
    generateKeyPair,
    exportPublicKey,
    importPublicKey,
    deriveAESKey,
    encrypt,
    decrypt,
    computeFingerprint
}

export default TrustGramCrypto
