// TrustGram Crypto — Public API
// This is the only file trustgram-ui interacts with.

import { generateIdentityBundle, exportPublicBundle, x3dhSend, x3dhReceive } from "./x3dh"
import { initSenderRatchet, initReceiverRatchet, ratchetEncrypt, ratchetDecrypt } from "./ratchet"
import { exportPublicKey, sha256, toBase64, fromBase64 } from "./primitives"
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

// Call once on first launch, store result in IndexedDB
export async function createIdentity(): Promise<IdentityKeyBundle> {
    return generateIdentityBundle()
}

// Export public keys to publish on server
export async function getPublicBundle(identity: IdentityKeyBundle): Promise<PublicKeyBundle> {
    return exportPublicBundle(identity)
}

// -------------------------
// Session establishment
// -------------------------

// Alice: initiate session with Bob
export async function initiateSession(
    myIdentity: IdentityKeyBundle,
    theirBundle: RecipientKeyBundle
): Promise<{ state: RatchetState, senderInfo: { identityKey: string, ephemeralKey: string, oneTimePreKeyId: string } }> {
    const { masterSecret, senderBundle } = await x3dhSend(myIdentity.identityKey, theirBundle)
    const state = await initSenderRatchet(masterSecret, theirBundle.signedPreKey)
    return { state, senderInfo: senderBundle }
}

// Bob: accept session from Alice
export async function acceptSession(
    myIdentity: IdentityKeyBundle,
    usedOneTimePreKey: string,
    senderIdentityKey: string,
    senderEphemeralKey: string
): Promise<RatchetState> {
    let usedOPK = null
    for (const kp of myIdentity.oneTimePreKeys) {
        const pub = await exportPublicKey(kp.publicKey)
        if (pub === usedOneTimePreKey) {
            usedOPK = kp
            break
        }
    }
    if (!usedOPK) throw new Error("One-time pre-key not found")

    const masterSecret = await x3dhReceive(
        myIdentity.identityKey,
        myIdentity.signedPreKey,
        usedOPK,
        senderIdentityKey,
        senderEphemeralKey
    )
    return initReceiverRatchet(masterSecret)
}

// -------------------------
// Messaging
// -------------------------

export async function encryptMessage(
    state: RatchetState,
    plaintext: string
): Promise<{ message: EncryptedMessage, state: RatchetState }> {
    return ratchetEncrypt(state, plaintext)
}

export async function decryptMessage(
    state: RatchetState,
    message: EncryptedMessage
): Promise<{ plaintext: string, state: RatchetState }> {
    return ratchetDecrypt(state, message)
}

// -------------------------
// Safety Numbers (Fingerprint)
// -------------------------

export async function computeFingerprint(
    myIdentity: IdentityKeyBundle,
    theirIdentityKeyB64: string
): Promise<Fingerprint> {
    const myPubRaw = await crypto.subtle.exportKey("raw", myIdentity.identityKey.publicKey)
    const theirPubRaw = fromBase64(theirIdentityKeyB64)

    const myArr = new Uint8Array(myPubRaw)
    const theirArr = new Uint8Array(theirPubRaw)

    // Sort lexicographically so both sides compute the same fingerprint
    let cmp = 0
    for (let i = 0; i < myArr.length && cmp === 0; i++) {
        cmp = myArr[i] - theirArr[i]
    }
    const combined = cmp < 0
        ? new Uint8Array([...myArr, ...theirArr])
        : new Uint8Array([...theirArr, ...myArr])

    const hash = await sha256(combined.buffer)
    const hex = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")

    const display = hex.match(/.{1,4}/g)!.join(" ")
    return { hex, display }
}
