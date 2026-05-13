import type { IdentityKeyBundle, PublicKeyBundle, RecipientKeyBundle, RatchetState, EncryptedMessage, Fingerprint } from "./types.ts";
export type { IdentityKeyBundle, PublicKeyBundle, RecipientKeyBundle, RatchetState, EncryptedMessage, Fingerprint };
export declare function createIdentity(): Promise<IdentityKeyBundle>;
export declare function getPublicBundle(identity: IdentityKeyBundle): Promise<PublicKeyBundle>;
export declare function initiateSession(myIdentity: IdentityKeyBundle, theirBundle: RecipientKeyBundle): Promise<{
    state: RatchetState;
    senderInfo: {
        identityKey: string;
        ephemeralKey: string;
        oneTimePreKeyId: string;
    };
}>;
export declare function acceptSession(myIdentity: IdentityKeyBundle, usedOneTimePreKey: string, senderIdentityKey: string, senderEphemeralKey: string): Promise<RatchetState>;
export declare function encryptMessage(state: RatchetState, plaintext: string): Promise<{
    message: EncryptedMessage;
    state: RatchetState;
}>;
export declare function decryptMessage(state: RatchetState, message: EncryptedMessage): Promise<{
    plaintext: string;
    state: RatchetState;
}>;
export declare function computeFingerprint(myIdentity: IdentityKeyBundle, theirIdentityKeyB64: string): Promise<Fingerprint>;
