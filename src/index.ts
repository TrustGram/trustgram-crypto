/**
 * TrustGram Crypto — Public API
 *
 * End-to-end encryption for TrustGram built on X3DH + Double Ratchet.
 * This is the only module trustgram-ui imports; all internals are hidden behind it.
 *
 * Typical flow:
 *   1. Each user calls `createIdentity()` once and stores the result in IndexedDB.
 *   2. Each user publishes their public bundle via `getPublicBundle()` to the server.
 *   3. Alice fetches Bob's bundle and calls `initiateSession()` → gets RatchetState + senderInfo.
 *   4. Alice sends `senderInfo` to Bob (via Telegram).
 *   5. Bob calls `acceptSession()` with his identity and Alice's senderInfo → gets RatchetState.
 *   6. Both sides use `encryptMessage` / `decryptMessage` passing the returned state each time.
 *   7. Optionally: both sides call `computeFingerprint` and compare out-of-band to detect MITM.
 */

import { generateIdentityBundle, exportPublicBundle, x3dhSend, x3dhReceive, signSignedPreKey } from "./x3dh"
import { initSenderRatchet, initReceiverRatchet, ratchetEncrypt, ratchetDecrypt } from "./ratchet"
import { exportPublicKey, exportSigningPublicKey, sha256, fromBase64 } from "./primitives"
import type {
    IdentityKeyBundle,
    PublicKeyBundle,
    RecipientKeyBundle,
    RatchetState,
    EncryptedMessage,
    Fingerprint
} from "./types.ts"

export type {
    IdentityKeyBundle,
    PublicKeyBundle,
    RecipientKeyBundle,
    RatchetState,
    EncryptedMessage,
    Fingerprint
}

// -------------------------
// Identity
// -------------------------

/**
 * Generate a new identity: IK + SPK + 10 OPKs.
 * Call once on first launch and persist the result in IndexedDB.
 * Private keys are non-extractable — they never leave WebCrypto memory.
 */
export async function createIdentity(): Promise<IdentityKeyBundle> {
    return generateIdentityBundle()
}

/**
 * Export the public halves of an identity bundle for publishing to the server.
 * Safe to transmit — contains no private key material.
 */
export async function getPublicBundle(identity: IdentityKeyBundle): Promise<PublicKeyBundle> {
    return exportPublicBundle(identity)
}

/**
 * Sign a freshly-rotated signed pre-key with the identity's long-term signing key.
 * Used when rotating the SPK without regenerating the rest of the identity.
 *
 * @returns base64 ECDSA signature over the raw public-key bytes.
 */
export async function signSPK(
    identity: IdentityKeyBundle,
    newSignedPreKey: { publicKey: CryptoKey }
): Promise<string> {
    return signSignedPreKey(identity.signingKey, newSignedPreKey.publicKey)
}

// -------------------------
// Session establishment
// -------------------------

/**
 * Alice: establish a session with Bob using his public key bundle.
 *
 * Runs X3DH to derive a master secret, then initialises the Double Ratchet.
 * @param theirBundle Bob's keys fetched from the server (server removes the OPK after delivery).
 * @returns `state` — Alice's initial ratchet state, ready to encrypt.
 *          `senderInfo` — must be sent to Bob so he can reproduce the master secret.
 */
export async function initiateSession(
    myIdentity: IdentityKeyBundle,
    theirBundle: RecipientKeyBundle
): Promise<{ state: RatchetState, senderInfo: { identityKey: string, ephemeralKey: string, oneTimePreKeyId: string } }> {
    const { masterSecret, senderBundle } = await x3dhSend(myIdentity.identityKey, theirBundle)
    const state = await initSenderRatchet(masterSecret, theirBundle.signedPreKey)
    return { state, senderInfo: senderBundle }
}

/**
 * Bob: accept a session initiated by Alice.
 *
 * Reproduces Alice's master secret by mirroring the X3DH operations, then
 * initialises the Double Ratchet using Bob's SPK as the initial ratchet key.
 * @param usedOneTimePreKey The OPK public key Alice used (from senderInfo.oneTimePreKeyId).
 * @param senderIdentityKey Alice's IK public key (base64).
 * @param senderEphemeralKey Alice's ephemeral key (base64).
 * @throws {Error} "One-time pre-key not found" if `usedOneTimePreKey` doesn't match any stored OPK.
 */
export async function acceptSession(
    myIdentity: IdentityKeyBundle,
    usedOneTimePreKey: string | null,
    senderIdentityKey: string,
    senderEphemeralKey: string
): Promise<RatchetState> {
    let usedOPK = null
    if (usedOneTimePreKey) {
        for (const kp of myIdentity.oneTimePreKeys) {
            const pub = await exportPublicKey(kp.publicKey)
            if (pub === usedOneTimePreKey) {
                usedOPK = kp
                break
            }
        }
        if (!usedOPK) throw new Error("One-time pre-key not found")
    }

    const masterSecret = await x3dhReceive(
        myIdentity.identityKey,
        myIdentity.signedPreKey,
        usedOPK,
        senderIdentityKey,
        senderEphemeralKey
    )
    return initReceiverRatchet(masterSecret, myIdentity.signedPreKey)
}

// -------------------------
// Messaging
// -------------------------

/**
 * Encrypt a plaintext string, advancing the ratchet state.
 * Always use the returned `state` for the next call — states are immutable.
 * @returns `message` — serialisable wire format; `state` — updated ratchet state.
 */
export async function encryptMessage(
    state: RatchetState,
    plaintext: string
): Promise<{ message: EncryptedMessage, state: RatchetState }> {
    return ratchetEncrypt(state, plaintext)
}

/**
 * Decrypt an incoming message, advancing the ratchet state.
 * Handles out-of-order delivery automatically (stores skipped keys internally).
 * Always use the returned `state` for the next call — states are immutable.
 * @throws {Error} If authentication fails (tampered data, wrong key, or too many skipped messages).
 */
export async function decryptMessage(
    state: RatchetState,
    message: EncryptedMessage
): Promise<{ plaintext: string, state: RatchetState }> {
    return ratchetDecrypt(state, message)
}

// -------------------------
// Safety Numbers (Fingerprint)
// -------------------------

/**
 * Compute a safety number from both parties' identity material.
 *
 * Binds **both** the ECDH identityKey and the ECDSA signingKey of each side —
 * otherwise an attacker could swap one half without affecting the fingerprint.
 *
 * Both users compute the same value regardless of who initiates — each side's
 * (identityKey || signingKey) is concatenated, then the two halves are sorted
 * lexicographically before hashing.
 */
export async function computeFingerprint(
    myIdentity: IdentityKeyBundle,
    theirIdentityKeyB64: string,
    theirSigningKeyB64: string
): Promise<Fingerprint> {
    const myIdRaw = new Uint8Array(await crypto.subtle.exportKey("raw", myIdentity.identityKey.publicKey))
    const mySignRaw = new Uint8Array(fromBase64(await exportSigningPublicKey(myIdentity.signingKey.publicKey)))
    const myHalf = new Uint8Array(myIdRaw.length + mySignRaw.length)
    myHalf.set(myIdRaw, 0)
    myHalf.set(mySignRaw, myIdRaw.length)

    const theirIdRaw = new Uint8Array(fromBase64(theirIdentityKeyB64))
    const theirSignRaw = new Uint8Array(fromBase64(theirSigningKeyB64))
    const theirHalf = new Uint8Array(theirIdRaw.length + theirSignRaw.length)
    theirHalf.set(theirIdRaw, 0)
    theirHalf.set(theirSignRaw, theirIdRaw.length)

    let cmp = 0
    const minLen = Math.min(myHalf.length, theirHalf.length)
    for (let i = 0; i < minLen && cmp === 0; i++) {
        cmp = myHalf[i] - theirHalf[i]
    }
    if (cmp === 0) cmp = myHalf.length - theirHalf.length

    const combined = cmp < 0
        ? new Uint8Array([...myHalf, ...theirHalf])
        : new Uint8Array([...theirHalf, ...myHalf])

    const hash = await sha256(combined.buffer)
    const hex = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")

    const display = hex.match(/.{1,4}/g)!.join(" ")
    return { hex, display }
}
