import type { RatchetState, EncryptedMessage } from "./types.ts";
export declare function initSenderRatchet(masterSecret: ArrayBuffer, theirPublicKeyB64: string): Promise<RatchetState>;
export declare function initReceiverRatchet(masterSecret: ArrayBuffer): Promise<RatchetState>;
export declare function ratchetEncrypt(state: RatchetState, plaintext: string): Promise<{
    message: EncryptedMessage;
    state: RatchetState;
}>;
export declare function ratchetDecrypt(state: RatchetState, message: EncryptedMessage): Promise<{
    plaintext: string;
    state: RatchetState;
}>;
