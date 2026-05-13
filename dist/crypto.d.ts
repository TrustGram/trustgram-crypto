export interface KeyPair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}
export interface EncryptedMessage {
    iv: string;
    ciphertext: string;
}
export interface Fingerprint {
    hex: string;
    display: string;
}
export declare function generateKeyPair(): Promise<KeyPair>;
export declare function exportPublicKey(key: CryptoKey): Promise<string>;
export declare function importPublicKey(b64: string): Promise<CryptoKey>;
export declare function deriveAESKey(privateKey: CryptoKey, theirPublicKey: CryptoKey): Promise<CryptoKey>;
export declare function encrypt(key: CryptoKey, plaintext: string): Promise<EncryptedMessage>;
export declare function decrypt(key: CryptoKey, iv: string, ciphertext: string): Promise<string>;
export declare function computeFingerprint(myPublicKey: CryptoKey, theirPublicKey: CryptoKey): Promise<Fingerprint>;
declare const TrustGramCrypto: {
    generateKeyPair: typeof generateKeyPair;
    exportPublicKey: typeof exportPublicKey;
    importPublicKey: typeof importPublicKey;
    deriveAESKey: typeof deriveAESKey;
    encrypt: typeof encrypt;
    decrypt: typeof decrypt;
    computeFingerprint: typeof computeFingerprint;
};
export default TrustGramCrypto;
