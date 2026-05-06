/**
 * Double Ratchet Algorithm.
 *
 * Combines a symmetric-key ratchet (chain key → message key) with a
 * Diffie-Hellman ratchet (new DH key pair on every reply). Properties:
 *   - Forward secrecy: past message keys are deleted after use.
 *   - Break-in recovery: compromise of current state doesn't expose future messages.
 *   - Out-of-order delivery: up to MAX_SKIP skipped keys are stored and retrieved as needed.
 *
 * State is immutable — every function returns a new RatchetState.
 */

import type { RatchetState, EncryptedMessage } from "./types"
import {
    generateKeyPair,
    exportPublicKey,
    importPublicKey,
    deriveBits,
    hkdfExpand,
    hkdf,
    aesEncrypt,
    aesDecrypt,
    toBase64,
    fromBase64
} from "./primitives"

const MAX_SKIP = 100 // maximum number of skipped message keys to store

// -------------------------
// Initialize ratchet
// -------------------------

/**
 * Initialize Alice's ratchet state after X3DH.
 * Immediately performs one DH ratchet step so Alice can start sending.
 * @param theirPublicKeyB64 Bob's SPK public key (base64) — Alice's first DH target.
 */
export async function initSenderRatchet(
    masterSecret: ArrayBuffer,
    theirPublicKeyB64: string
): Promise<RatchetState> {
    const dhSendKey = await generateKeyPair()
    const theirPub = await importPublicKey(theirPublicKeyB64)

    const dh = await deriveBits(dhSendKey.privateKey, theirPub)
    const { key1: rootKey, key2: sendChainKey } = await hkdfExpand(
        masterSecret,
        dh,
        "TrustGram_Ratchet_v1"
    )

    return {
        dhSendKey,
        dhRecvKey: theirPub,
        rootKey,
        sendChainKey,
        recvChainKey: null,
        sendCount: 0,
        recvCount: 0,
        prevSendCount: 0,
        skippedKeys: []
    }
}

/**
 * Initialize Bob's ratchet state after X3DH.
 * Bob uses his SPK as the initial DH send key so Alice's first DH step
 * (ECDH with Bob's SPK) produces the same chain key on both sides.
 */
export async function initReceiverRatchet(
    masterSecret: ArrayBuffer,
    spkKeyPair: { privateKey: CryptoKey, publicKey: CryptoKey }
): Promise<RatchetState> {
    return {
        dhSendKey: spkKeyPair,
        dhRecvKey: null,
        rootKey: masterSecret,
        sendChainKey: null,
        recvChainKey: null,
        sendCount: 0,
        recvCount: 0,
        prevSendCount: 0,
        skippedKeys: []
    }
}

// -------------------------
// Encrypt
// -------------------------

/**
 * Encrypt one message, advancing the symmetric sending chain.
 * DH send key is unchanged until a message from the other side is decrypted.
 */
export async function ratchetEncrypt(
    state: RatchetState,
    plaintext: string
): Promise<{ message: EncryptedMessage, state: RatchetState }> {
    const { messageKey, nextChainKey } = await advanceChain(state.sendChainKey!)

    const dhPub = await exportPublicKey(state.dhSendKey.publicKey)
    const { iv, ciphertext } = await aesEncrypt(messageKey, plaintext)

    const message: EncryptedMessage = {
        dhPub,
        n: state.sendCount,
        pn: state.prevSendCount,
        iv,
        ciphertext
    }

    const nextState: RatchetState = {
        ...state,
        sendChainKey: nextChainKey,
        sendCount: state.sendCount + 1
    }

    return { message, state: nextState }
}

// -------------------------
// Decrypt
// -------------------------

/**
 * Decrypt one message, advancing the ratchet as needed.
 *
 * Three cases handled:
 *   1. Skipped message — key is already stored in `state.skippedKeys`.
 *   2. Same DH key as last received — advance symmetric chain only.
 *   3. New DH key — perform DH ratchet step first, then advance symmetric chain.
 *
 * Throws if more than MAX_SKIP messages are skipped (DoS protection).
 */
export async function ratchetDecrypt(
    state: RatchetState,
    message: EncryptedMessage
): Promise<{ plaintext: string, state: RatchetState }> {
    // Case 1: out-of-order — key was saved during a previous decrypt
    const skipped = state.skippedKeys.find(
        k => k.dhKey === message.dhPub && k.n === message.n
    )

    if (skipped) {
        const plaintext = await aesDecrypt(skipped.messageKey, message.iv, message.ciphertext)
        const nextState: RatchetState = {
            ...state,
            skippedKeys: state.skippedKeys.filter(k => k !== skipped)
        }
        return { plaintext, state: nextState }
    }

    let currentState = state

    // Case 3: new DH key from sender → DH ratchet step
    const theirDhPub = await importPublicKey(message.dhPub)
    const isDHRatchetNeeded = !state.dhRecvKey ||
        await exportPublicKey(state.dhRecvKey) !== message.dhPub

    if (isDHRatchetNeeded) {
        currentState = await skipMessageKeys(currentState, message.pn)
        currentState = await dhRatchetStep(currentState, theirDhPub)
    }

    // Case 2 (and tail of case 3): advance symmetric chain to message.n
    currentState = await skipMessageKeys(currentState, message.n)

    const { messageKey, nextChainKey } = await advanceChain(currentState.recvChainKey!)
    const plaintext = await aesDecrypt(messageKey, message.iv, message.ciphertext)

    const nextState: RatchetState = {
        ...currentState,
        recvChainKey: nextChainKey,
        recvCount: currentState.recvCount + 1
    }

    return { plaintext, state: nextState }
}

// -------------------------
// Internal helpers
// -------------------------

/** Perform one DH ratchet step: derive new recv chain, generate new DH send key, derive new send chain. */
async function dhRatchetStep(state: RatchetState, theirPub: CryptoKey): Promise<RatchetState> {
    const dh1 = await deriveBits(state.dhSendKey.privateKey, theirPub)
    const { key1: rootKey1, key2: recvChainKey } = await hkdfExpand(
        state.rootKey, dh1, "TrustGram_Ratchet_v1"
    )

    const newDhSendKey = await generateKeyPair()
    const dh2 = await deriveBits(newDhSendKey.privateKey, theirPub)
    const { key1: rootKey2, key2: sendChainKey } = await hkdfExpand(
        rootKey1, dh2, "TrustGram_Ratchet_v1"
    )

    return {
        ...state,
        dhSendKey: newDhSendKey,
        dhRecvKey: theirPub,
        rootKey: rootKey2,
        sendChainKey,
        recvChainKey,
        prevSendCount: state.sendCount,
        sendCount: 0,
        recvCount: 0
    }
}

/** Advance a chain key once: derive message key and next chain key via HKDF. */
async function advanceChain(
    chainKey: ArrayBuffer
): Promise<{ messageKey: ArrayBuffer, nextChainKey: ArrayBuffer }> {
    const salt = new Uint8Array(32).fill(0).buffer
    const messageKey = await hkdf(chainKey, salt, "TrustGram_MessageKey_v1")
    const nextChainKey = await hkdf(chainKey, salt, "TrustGram_ChainKey_v1")
    return { messageKey, nextChainKey }
}

/**
 * Advance the receiving chain to `until`, saving each derived key in skippedKeys.
 * Called before decrypting so out-of-order messages can be decrypted later.
 * Throws if the gap exceeds MAX_SKIP (prevents unbounded memory growth).
 */
async function skipMessageKeys(state: RatchetState, until: number): Promise<RatchetState> {
    if (until - state.recvCount > MAX_SKIP) {
        throw new Error("Too many skipped messages")
    }

    let chainKey = state.recvChainKey
    const skippedKeys = [...state.skippedKeys]
    let recvCount = state.recvCount

    while (recvCount < until) {
        const { messageKey, nextChainKey } = await advanceChain(chainKey!)
        skippedKeys.push({
            dhKey: await exportPublicKey(state.dhRecvKey!),
            n: recvCount,
            messageKey
        })
        chainKey = nextChainKey
        recvCount++
    }

    return { ...state, recvChainKey: chainKey, recvCount, skippedKeys }
}
