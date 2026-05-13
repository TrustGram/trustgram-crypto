// TrustGram Crypto — Public API
// This is the only file trustgram-ui interacts with.
import { generateIdentityBundle, exportPublicBundle, x3dhSend, x3dhReceive } from "./x3dh.ts";
import { initSenderRatchet, initReceiverRatchet, ratchetEncrypt, ratchetDecrypt } from "./ratchet.ts";
import { exportPublicKey, sha256, fromBase64 } from "./primitives.ts";
// -------------------------
// Identity
// -------------------------
// Call once on first launch, store result in IndexedDB
export async function createIdentity() {
    return generateIdentityBundle();
}
// Export public keys to publish on server
export async function getPublicBundle(identity) {
    return exportPublicBundle(identity);
}
// -------------------------
// Session establishment
// -------------------------
// Alice: initiate session with Bob
export async function initiateSession(myIdentity, theirBundle) {
    const { masterSecret, senderBundle } = await x3dhSend(myIdentity.identityKey, theirBundle);
    const state = await initSenderRatchet(masterSecret, theirBundle.signedPreKey);
    return { state, senderInfo: senderBundle };
}
// Bob: accept session from Alice
export async function acceptSession(myIdentity, usedOneTimePreKey, senderIdentityKey, senderEphemeralKey) {
    const usedOPK = myIdentity.oneTimePreKeys.find(async (kp) => await exportPublicKey(kp.publicKey) === usedOneTimePreKey);
    if (!usedOPK)
        throw new Error("One-time pre-key not found");
    const masterSecret = await x3dhReceive(myIdentity.identityKey, myIdentity.signedPreKey, usedOPK, senderIdentityKey, senderEphemeralKey);
    return initReceiverRatchet(masterSecret);
}
// -------------------------
// Messaging
// -------------------------
export async function encryptMessage(state, plaintext) {
    return ratchetEncrypt(state, plaintext);
}
export async function decryptMessage(state, message) {
    return ratchetDecrypt(state, message);
}
// -------------------------
// Safety Numbers (Fingerprint)
// -------------------------
export async function computeFingerprint(myIdentity, theirIdentityKeyB64) {
    const myPubRaw = await crypto.subtle.exportKey("raw", myIdentity.identityKey.publicKey);
    const theirPubRaw = fromBase64(theirIdentityKeyB64);
    const myArr = new Uint8Array(myPubRaw);
    const theirArr = new Uint8Array(theirPubRaw);
    // Sort so both sides compute the same fingerprint
    const combined = myArr[0] < theirArr[0]
        ? new Uint8Array([...myArr, ...theirArr])
        : new Uint8Array([...theirArr, ...myArr]);
    const hash = await sha256(combined.buffer);
    const hex = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    const display = hex.match(/.{1,4}/g).join(" ");
    return { hex, display };
}
