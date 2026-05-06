// Double Ratchet Algorithm
// Provides forward secrecy and break-in recovery.
// Each message is encrypted with a unique key derived from a ratcheting chain.

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

const MAX_SKIP = 100 // max skipped messages to store

// -------------------------
// Initialize ratchet
// -------------------------

// Called by the session initiator (Alice) after X3DH
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

// Called by the session receiver (Bob) after X3DH
// Bob uses his SPK as the initial ratchet key so Alice can derive the same chain
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

export async function ratchetDecrypt(
    state: RatchetState,
    message: EncryptedMessage
): Promise<{ plaintext: string, state: RatchetState }> {
    // Check if we have a skipped key for this message
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

    // DH ratchet step if we see a new DH public key
    const theirDhPub = await importPublicKey(message.dhPub)
    const isDHRatchetNeeded = !state.dhRecvKey ||
        await exportPublicKey(state.dhRecvKey) !== message.dhPub

    if (isDHRatchetNeeded) {
        // Store skipped keys from current receiving chain
        currentState = await skipMessageKeys(currentState, message.pn)

        // Perform DH ratchet
        currentState = await dhRatchetStep(currentState, theirDhPub)
    }

    // Store skipped keys up to message.n
    currentState = await skipMessageKeys(currentState, message.n)

    // Decrypt with next message key
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

async function dhRatchetStep(state: RatchetState, theirPub: CryptoKey): Promise<RatchetState> {
    // Derive new recv chain key
    const dh1 = await deriveBits(state.dhSendKey.privateKey, theirPub)
    const { key1: rootKey1, key2: recvChainKey } = await hkdfExpand(
        state.rootKey, dh1, "TrustGram_Ratchet_v1"
    )

    // Generate new DH send key
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

async function advanceChain(
    chainKey: ArrayBuffer
): Promise<{ messageKey: ArrayBuffer, nextChainKey: ArrayBuffer }> {
    const salt = new Uint8Array(32).fill(0).buffer
    const messageKey = await hkdf(chainKey, salt, "TrustGram_MessageKey_v1")
    const nextChainKey = await hkdf(chainKey, salt, "TrustGram_ChainKey_v1")
    return { messageKey, nextChainKey }
}

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
