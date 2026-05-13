import type { KeyPair, RecipientKeyBundle, X3DHResult, PublicKeyBundle, IdentityKeyBundle } from "./types.ts";
export declare function generateIdentityBundle(): Promise<IdentityKeyBundle>;
export declare function exportPublicBundle(bundle: IdentityKeyBundle): Promise<PublicKeyBundle>;
export declare function x3dhSend(myIdentityKey: KeyPair, recipientBundle: RecipientKeyBundle): Promise<X3DHResult>;
export declare function x3dhReceive(myIdentityKey: KeyPair, mySignedPreKey: KeyPair, myOneTimePreKey: KeyPair, senderIdentityKeyB64: string, senderEphemeralKeyB64: string): Promise<ArrayBuffer>;
