// Low-level Web Crypto API wrappers.
// No business logic here — only raw cryptographic operations.

import type { KeyPair } from "./types.ts"

// -------------------------
// Encoding helpers
// -------------------------

export function toBase64(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
}

export function fromBase64(b64: string): ArrayBuffer {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer
}

// -------------------------
// ECDH
// -------------------------

export async function generateKeyPair(): Promise<KeyPair> {
    return crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey", "deriveBits"]
    ) as Promise<KeyPair>
}

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

export async function deriveBits(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        256
    )
}

// -------------------------
// HKDF
// -------------------------

export async function hkdf(
    inputKey: ArrayBuffer,
    salt: ArrayBuffer,
    info: string,
    length: number = 32
): Promise<ArrayBuffer> {
    const key = await crypto.subtle.importKey(
        "raw", inputKey, "HKDF", false, ["deriveBits"]
    )
    return crypto.subtle.deriveBits(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt,
            info: new TextEncoder().encode(info)
        },
        key,
        length * 8
    )
}

// Derive two keys from one input (root key derivation in Double Ratchet)
export async function hkdfExpand(
    inputKey: ArrayBuffer,
    salt: ArrayBuffer,
    info: string
): Promise<{ key1: ArrayBuffer, key2: ArrayBuffer }> {
    const output = await hkdf(inputKey, salt, info, 64)
    return {
        key1: output.slice(0, 32),
        key2: output.slice(32, 64)
    }
}

// -------------------------
// AES-256-GCM
// -------------------------

export async function importAESKey(raw: ArrayBuffer): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    )
}

export async function aesEncrypt(
    keyBytes: ArrayBuffer,
    plaintext: string
): Promise<{ iv: string, ciphertext: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const key = await importAESKey(keyBytes)
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

export async function aesDecrypt(
    keyBytes: ArrayBuffer,
    iv: string,
    ciphertext: string
): Promise<string> {
    const key = await importAESKey(keyBytes)
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(iv) },
        key,
        fromBase64(ciphertext)
    )
    return new TextDecoder().decode(decrypted)
}

// -------------------------
// SHA-256
// -------------------------

export async function sha256(data: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.digest("SHA-256", data)
}
