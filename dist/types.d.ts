export interface KeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}
export interface IdentityKeyBundle {
    identityKey: KeyPair;
    signedPreKey: KeyPair;
    oneTimePreKeys: KeyPair[];
}
export interface PublicKeyBundle {
    identityKey: string;
    signedPreKey: string;
    oneTimePreKeys: string[];
}
export interface RecipientKeyBundle {
    identityKey: string;
    signedPreKey: string;
    oneTimePreKey: string;
}
export interface X3DHSenderBundle {
    identityKey: string;
    ephemeralKey: string;
    oneTimePreKeyId: string;
}
export interface X3DHResult {
    masterSecret: ArrayBuffer;
    senderBundle: X3DHSenderBundle;
}
export interface RatchetState {
    dhSendKey: KeyPair;
    dhRecvKey: CryptoKey | null;
    rootKey: ArrayBuffer;
    sendChainKey: ArrayBuffer | null;
    recvChainKey: ArrayBuffer | null;
    sendCount: number;
    recvCount: number;
    prevSendCount: number;
    skippedKeys: SkippedKey[];
}
export interface SkippedKey {
    dhKey: string;
    n: number;
    messageKey: ArrayBuffer;
}
export interface EncryptedMessage {
    dhPub: string;
    n: number;
    pn: number;
    iv: string;
    ciphertext: string;
}
export interface DecryptedMessage {
    plaintext: string;
    senderDhPub: string;
}
export interface Fingerprint {
    hex: string;
    display: string;
}
