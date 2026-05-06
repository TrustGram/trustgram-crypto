// X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
// Used to establish an initial shared secret between two parties
// without requiring both to be online simultaneously.

import type { KeyPair, RecipientKeyBundle, X3DHResult, PublicKeyBundle, IdentityKeyBundle } from "./types.ts"
import { generateKeyPair, exportPublicKey, importPublicKey, deriveBits, hkdf, toBase64 } from "./primitives.ts"

const ONE_TIME_PREKEY_COUNT = 10

// -------------------------
// Bundle generation (Bob does this on first launch)
// -------------------------

export async function generateIdentityBundle(): Promise<IdentityKeyBundle> {
    const identityKey = await generateKeyPair()
    const signedPreKey = await generateKeyPair()
    const oneTimePreKeys: KeyPair[] = []
    for (let i = 0; i < ONE_TIME_PREKEY_COUNT; i++) {
        oneTimePreKeys.push(await generateKeyPair())
    }
    return { identityKey, signedPreKey, oneTimePreKeys }
}

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

export async function x3dhSend(
    myIdentityKey: KeyPair,
    recipientBundle: RecipientKeyBundle
): Promise<X3DHResult> {
    const ephemeralKey = await generateKeyPair()

    const theirIK = await importPublicKey(recipientBundle.identityKey)
    const theirSPK = await importPublicKey(recipientBundle.signedPreKey)
    const theirOPK = await importPublicKey(recipientBundle.oneTimePreKey)

    // 4 ECDH operations
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

export async function x3dhReceive(
    myIdentityKey: KeyPair,
    mySignedPreKey: KeyPair,
    myOneTimePreKey: KeyPair,
    senderIdentityKeyB64: string,
    senderEphemeralKeyB64: string
): Promise<ArrayBuffer> {
    const theirIK = await importPublicKey(senderIdentityKeyB64)
    const theirEK = await importPublicKey(senderEphemeralKeyB64)

    // Mirror of sender's 4 ECDH operations
    const dh1 = await deriveBits(mySignedPreKey.privateKey, theirIK)   // SPK_B + IK_A
    const dh2 = await deriveBits(myIdentityKey.privateKey, theirEK)     // IK_B + EK_A
    const dh3 = await deriveBits(mySignedPreKey.privateKey, theirEK)    // SPK_B + EK_A
    const dh4 = await deriveBits(myOneTimePreKey.privateKey, theirEK)   // OPK_B + EK_A

    return combineDH(dh1, dh2, dh3, dh4)
}

// -------------------------
// Helpers
// -------------------------

async function combineDH(
    dh1: ArrayBuffer,
    dh2: ArrayBuffer,
    dh3: ArrayBuffer,
    dh4: ArrayBuffer
): Promise<ArrayBuffer> {
    // Concatenate all DH outputs
    const combined = new Uint8Array(128)
    combined.set(new Uint8Array(dh1), 0)
    combined.set(new Uint8Array(dh2), 32)
    combined.set(new Uint8Array(dh3), 64)
    combined.set(new Uint8Array(dh4), 96)

    // HKDF to derive master secret
    const salt = new Uint8Array(32).fill(0).buffer
    return hkdf(combined.buffer, salt, "TrustGram_X3DH_v1")
}
