import type { KeyPair } from "./types.ts";
export declare function toBase64(buf: ArrayBuffer): string;
export declare function fromBase64(b64: string): ArrayBuffer;
export declare function generateKeyPair(): Promise<KeyPair>;
export declare function exportPublicKey(key: CryptoKey): Promise<string>;
export declare function importPublicKey(b64: string): Promise<CryptoKey>;
export declare function deriveBits(privateKey: CryptoKey, publicKey: CryptoKey): Promise<ArrayBuffer>;
export declare function hkdf(inputKey: ArrayBuffer, salt: ArrayBuffer, info: string, length?: number): Promise<ArrayBuffer>;
export declare function hkdfExpand(inputKey: ArrayBuffer, salt: ArrayBuffer, info: string): Promise<{
    key1: ArrayBuffer;
    key2: ArrayBuffer;
}>;
export declare function importAESKey(raw: ArrayBuffer): Promise<CryptoKey>;
export declare function aesEncrypt(keyBytes: ArrayBuffer, plaintext: string): Promise<{
    iv: string;
    ciphertext: string;
}>;
export declare function aesDecrypt(keyBytes: ArrayBuffer, iv: string, ciphertext: string): Promise<string>;
export declare function sha256(data: ArrayBuffer): Promise<ArrayBuffer>;
