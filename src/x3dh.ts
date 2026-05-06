/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 *
 * Establishes a shared master secret between Alice and Bob without requiring
 * both to be online at the same time. Alice fetches Bob's published keys,
 * runs 4 ECDH operations, and sends Bob the public halves he needs to mirror them.
 *
 * Key roles:
 *   IK  — long-term Identity Key
 *   SPK — Signed Pre-Key (rotated periodically)
 *   OPK — One-Time Pre-Key (consumed once, provides forward secrecy)
 *   EK  — Ephemeral Key generated fresh by Alice for each session
 */

import type { KeyPair, RecipientKeyBundle, X3DHResult, PublicKeyBundle, IdentityKeyBundle } from "./types"
import { generateKeyPair, exportPublicKey, importPublicKey, deriveBits, hkdf, toBase64 } from "./primitives"

const ONE_TIME_PREKEY_COUNT = 10

// -------------------------
// Bundle generation (Bob does this on first launch)
// -------------------------

/** Generate a full identity bundle: IK + SPK + 10 OPKs. Store result in IndexedDB. */
export async function generateIdentityBundle(): Promise<IdentityKeyBundle> {
    const identityKey = await generateKeyPair()
    const signedPreKey = await generateKeyPair()
    const oneTimePreKeys: KeyPair[] = []
    for (let i = 0; i < ONE_TIME_PREKEY_COUNT; i++) {
        oneTimePreKeys.push(await generateKeyPair())
    }
    return { identityKey, signedPreKey, oneTimePreKeys }
}

/** Extract the public keys from an identity bundle for publishing to the server. */
export async function exportPublicBundle(bundle: IdentityKeyBundle): Promise<PublicKeyBundle> {
    return {
        identityKey: await exportPublicKey(bundle.identityKey.publicKey),
        signedPreKey: await exportPublicKey(bundle.signedPreKey.publicKey),
        oneTimePreKeys: await Promise.all(
            bundle.oneTimePreKeys.map(kp => exportPublicKey(kp.publicKey))
        )
    }
}

// -------------------------
// X3DH sender side (Alice)
// -------------------------

/**
 * Alice's side of X3DH: derive a master secret from Bob's public bundle.
 *
 * Performs 4 ECDH operations:
 *   DH1 = ECDH(IK_A, SPK_B)
 *   DH2 = ECDH(EK_A, IK_B)
 *   DH3 = ECDH(EK_A, SPK_B)
 *   DH4 = ECDH(EK_A, OPK_B)
 *
 * @returns masterSecret and senderBundle (Alice's public keys for Bob to reproduce the secret).
 */
export async function x3dhSend(
    myIdentityKey: KeyPair,
    recipientBundle: RecipientKeyBundle
): Promise<X3DHResult> {
    const ephemeralKey = await generateKeyPair()

    const theirIK = await importPublicKey(recipientBundle.identityKey)
    const theirSPK = await importPublicKey(recipientBundle.signedPreKey)
    const theirOPK = await importPublicKey(recipientBundle.oneTimePreKey)

    const dh1 = await deriveBits(myIdentityKey.privateKey, theirSPK)  // IK_A + SPK_B
    const dh2 = await deriveBits(ephemeralKey.privateKey, theirIK)     // EK_A + IK_B
    const dh3 = await deriveBits(ephemeralKey.privateKey, theirSPK)    // EK_A + SPK_B
    const dh4 = await deriveBits(ephemeralKey.privateKey, theirOPK)    // EK_A + OPK_B

    const masterSecret = await combineDH(dh1, dh2, dh3, dh4)

    return {
        masterSecret,
        senderBundle: {
            identityKey: await exportPublicKey(myIdentityKey.publicKey),
            ephemeralKey: await exportPublicKey(ephemeralKey.publicKey),
            oneTimePreKeyId: recipientBundle.oneTimePreKey
        }
    }
}

// -------------------------
// X3DH receiver side (Bob)
// -------------------------

/**
 * Bob's side of X3DH: reproduce Alice's master secret using his private keys.
 *
 * Mirrors Alice's 4 ECDH operations (ECDH is commutative):
 *   DH1 = ECDH(SPK_B, IK_A)
 *   DH2 = ECDH(IK_B,  EK_A)
 *   DH3 = ECDH(SPK_B, EK_A)
 *   DH4 = ECDH(OPK_B, EK_A)
 *
 * @returns The same masterSecret Alice computed, ready to seed the Double Ratchet.
 */
export async function x3dhReceive(
    myIdentityKey: KeyPair,
    mySignedPreKey: KeyPair,
    myOneTimePreKey: KeyPair,
    senderIdentityKeyB64: string,
    senderEphemeralKeyB64: string
): Promise<ArrayBuffer> {
    const theirIK = await importPublicKey(senderIdentityKeyB64)
    const theirEK = await importPublicKey(senderEphemeralKeyB64)

    const dh1 = await deriveBits(mySignedPreKey.privateKey, theirIK)   // SPK_B + IK_A
    const dh2 = await deriveBits(myIdentityKey.privateKey, theirEK)     // IK_B + EK_A
    const dh3 = await deriveBits(mySignedPreKey.privateKey, theirEK)    // SPK_B + EK_A
    const dh4 = await deriveBits(myOneTimePreKey.privateKey, theirEK)   // OPK_B + EK_A

    return combineDH(dh1, dh2, dh3, dh4)
}

// -------------------------
// Helpers
// -------------------------

/** Concatenate 4 ECDH outputs (128 bytes) and derive a 32-byte master secret via HKDF. */
async function combineDH(
    dh1: ArrayBuffer,
    dh2: ArrayBuffer,
    dh3: ArrayBuffer,
    dh4: ArrayBuffer
): Promise<ArrayBuffer> {
    const combined = new Uint8Array(128)
    combined.set(new Uint8Array(dh1), 0)
    combined.set(new Uint8Array(dh2), 32)
    combined.set(new Uint8Array(dh3), 64)
    combined.set(new Uint8Array(dh4), 96)

    const salt = new Uint8Array(32).fill(0).buffer
    return hkdf(combined.buffer, salt, "TrustGram_X3DH_v1")
}
