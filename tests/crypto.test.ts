import { test, expect } from "@playwright/test"
import MCR from "monocart-reporter"

// Load dist files in a real browser context
test.beforeEach(async ({ page }) => {
    await page.coverage.startJSCoverage()
    await page.goto("http://localhost:3000/tests/test.html")
    await page.waitForFunction(() => (window as any).__cryptoReady === true)
})

test.afterEach(async ({ page }, testInfo) => {
    const coverage = await page.coverage.stopJSCoverage()
    await MCR.addCoverageReport(coverage, testInfo)
})

// -------------------------
// Identity & Keys
// -------------------------

test("createIdentity returns a full key bundle", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const kp = await TrustGramCrypto.createIdentity()
        return {
            hasIdentityKey: !!kp.identityKey,
            hasSignedPreKey: !!kp.signedPreKey,
            hasOneTimePreKeys: kp.oneTimePreKeys.length === 10
        }
    })
    expect(result.hasIdentityKey).toBe(true)
    expect(result.hasSignedPreKey).toBe(true)
    expect(result.hasOneTimePreKeys).toBe(true)
})

test("public bundle exports correctly", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const identity = await TrustGramCrypto.createIdentity()
        const bundle = await TrustGramCrypto.getPublicBundle(identity)
        return {
            hasIdentityKey: typeof bundle.identityKey === "string",
            hasSignedPreKey: typeof bundle.signedPreKey === "string",
            hasOneTimePreKeys: bundle.oneTimePreKeys.length === 10
        }
    })
    expect(result.hasIdentityKey).toBe(true)
    expect(result.hasSignedPreKey).toBe(true)
    expect(result.hasOneTimePreKeys).toBe(true)
})

test("two identities have different public keys", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const alicePub = (await TrustGramCrypto.getPublicBundle(alice)).identityKey
        const bobPub = (await TrustGramCrypto.getPublicBundle(bob)).identityKey
        return alicePub !== bobPub
    })
    expect(result).toBe(true)
})

// -------------------------
// Helpers
// -------------------------

async function setupSession(page: any) {
    return page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const bobState = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            senderInfo.identityKey,
            senderInfo.ephemeralKey
        )
        return { aliceState, bobState }
    })
}

// -------------------------
// Encryption / Decryption
// -------------------------

test("encrypt and decrypt round-trip", async ({ page }) => {
    const plaintext = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, "hello bob")
        const bobState = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            senderInfo.identityKey,
            senderInfo.ephemeralKey
        )
        const { plaintext } = await TrustGramCrypto.decryptMessage(bobState, message)
        return plaintext
    })
    expect(plaintext).toBe("hello bob")
})

test("multiple messages in sequence", async ({ page }) => {
    const results = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState0, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        let bobState = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            senderInfo.identityKey,
            senderInfo.ephemeralKey
        )

        const messages = ["first", "second", "third"]
        let aliceState = aliceState0
        const encrypted = []

        for (const msg of messages) {
            const { message, state } = await TrustGramCrypto.encryptMessage(aliceState, msg)
            aliceState = state
            encrypted.push(message)
        }

        const decrypted = []
        for (const msg of encrypted) {
            const { plaintext, state } = await TrustGramCrypto.decryptMessage(bobState, msg)
            bobState = state
            decrypted.push(plaintext)
        }

        return decrypted
    })
    expect(results).toEqual(["first", "second", "third"])
})

test("bidirectional messaging", async ({ page }) => {
    const results = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState0, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        let bobState0 = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            senderInfo.identityKey,
            senderInfo.ephemeralKey
        )

        // Alice → Bob
        const { message: msg1, state: aliceState1 } = await TrustGramCrypto.encryptMessage(aliceState0, "hi bob")
        const { plaintext: plain1, state: bobState1 } = await TrustGramCrypto.decryptMessage(bobState0, msg1)

        // Bob → Alice
        const { message: msg2, state: bobState2 } = await TrustGramCrypto.encryptMessage(bobState1, "hi alice")
        const { plaintext: plain2, state: aliceState2 } = await TrustGramCrypto.decryptMessage(aliceState1, msg2)

        // Alice → Bob again
        const { message: msg3 } = await TrustGramCrypto.encryptMessage(aliceState2, "how are you")
        const { plaintext: plain3 } = await TrustGramCrypto.decryptMessage(bobState2, msg3)

        return [plain1, plain2, plain3]
    })
    expect(results).toEqual(["hi bob", "hi alice", "how are you"])
})

test("empty string encrypts and decrypts", async ({ page }) => {
    const plaintext = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, "")
        const bobState = await TrustGramCrypto.acceptSession(
            bob, recipientBundle.oneTimePreKey, senderInfo.identityKey, senderInfo.ephemeralKey
        )
        const { plaintext } = await TrustGramCrypto.decryptMessage(bobState, message)
        return plaintext
    })
    expect(plaintext).toBe("")
})

test("long message encrypts and decrypts", async ({ page }) => {
    const original = "a".repeat(10000)
    const plaintext = await page.evaluate(async (original) => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, original)
        const bobState = await TrustGramCrypto.acceptSession(
            bob, recipientBundle.oneTimePreKey, senderInfo.identityKey, senderInfo.ephemeralKey
        )
        const { plaintext } = await TrustGramCrypto.decryptMessage(bobState, message)
        return plaintext
    }, original)
    expect(plaintext).toBe(original)
})

test("each message has unique ciphertext", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState0 } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message: msg1, state: aliceState1 } = await TrustGramCrypto.encryptMessage(aliceState0, "same text")
        const { message: msg2 } = await TrustGramCrypto.encryptMessage(aliceState1, "same text")
        return msg1.ciphertext !== msg2.ciphertext
    })
    expect(result).toBe(true)
})

// -------------------------
// Security
// -------------------------

test("tampered ciphertext fails to decrypt", async ({ page }) => {
    const error = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, "secret")
        const tampered = { ...message, ciphertext: message.ciphertext.slice(0, -4) + "AAAA" }
        const bobState = await TrustGramCrypto.acceptSession(
            bob, recipientBundle.oneTimePreKey, senderInfo.identityKey, senderInfo.ephemeralKey
        )
        try {
            await TrustGramCrypto.decryptMessage(bobState, tampered)
            return null
        } catch (e: any) {
            return e.message
        }
    })
    expect(error).not.toBeNull()
})

test("wrong key fails to decrypt", async ({ page }) => {
    const error = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const eve = await TrustGramCrypto.createIdentity()

        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, "secret")

        // Eve tries to decrypt with her own session
        const evePublicBundle = await TrustGramCrypto.getPublicBundle(eve)
        const eveBundle = {
            identityKey: evePublicBundle.identityKey,
            signedPreKey: evePublicBundle.signedPreKey,
            oneTimePreKey: evePublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceEveState, senderInfo: eveSenderInfo } = await TrustGramCrypto.initiateSession(alice, eveBundle)
        const eveState = await TrustGramCrypto.acceptSession(
            eve, eveBundle.oneTimePreKey, eveSenderInfo.identityKey, eveSenderInfo.ephemeralKey
        )
        try {
            await TrustGramCrypto.decryptMessage(eveState, message)
            return null
        } catch (e: any) {
            return e.message
        }
    })
    expect(error).not.toBeNull()
})

test("two sessions are independent", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)

        // Session 1
        const bundle1 = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState1, senderInfo: si1 } = await TrustGramCrypto.initiateSession(alice, bundle1)
        const { message: msg1 } = await TrustGramCrypto.encryptMessage(aliceState1, "session one")
        const bobState1 = await TrustGramCrypto.acceptSession(bob, bundle1.oneTimePreKey, si1.identityKey, si1.ephemeralKey)
        const { plaintext: p1 } = await TrustGramCrypto.decryptMessage(bobState1, msg1)

        // Session 2 (different OPK)
        const bundle2 = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[1]
        }
        const { state: aliceState2, senderInfo: si2 } = await TrustGramCrypto.initiateSession(alice, bundle2)
        const { message: msg2 } = await TrustGramCrypto.encryptMessage(aliceState2, "session two")
        const bobState2 = await TrustGramCrypto.acceptSession(bob, bundle2.oneTimePreKey, si2.identityKey, si2.ephemeralKey)
        const { plaintext: p2 } = await TrustGramCrypto.decryptMessage(bobState2, msg2)

        return [p1, p2]
    })
    expect(result).toEqual(["session one", "session two"])
})

// -------------------------
// Fingerprint
// -------------------------

test("fingerprint is same for both parties", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const alicePub = (await TrustGramCrypto.getPublicBundle(alice)).identityKey
        const bobPub = (await TrustGramCrypto.getPublicBundle(bob)).identityKey
        const fp1 = await TrustGramCrypto.computeFingerprint(alice, bobPub)
        const fp2 = await TrustGramCrypto.computeFingerprint(bob, alicePub)
        return { fp1: fp1.hex, fp2: fp2.hex }
    })
    expect(result.fp1).toBe(result.fp2)
})

test("fingerprint differs for different pairs", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const eve = await TrustGramCrypto.createIdentity()
        const bobPub = (await TrustGramCrypto.getPublicBundle(bob)).identityKey
        const evePub = (await TrustGramCrypto.getPublicBundle(eve)).identityKey
        const fp1 = await TrustGramCrypto.computeFingerprint(alice, bobPub)
        const fp2 = await TrustGramCrypto.computeFingerprint(alice, evePub)
        return fp1.hex !== fp2.hex
    })
    expect(result).toBe(true)
})

test("fingerprint display format is readable", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPub = (await TrustGramCrypto.getPublicBundle(bob)).identityKey
        const fp = await TrustGramCrypto.computeFingerprint(alice, bobPub)
        return fp.display
    })
    expect(result).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4})+$/)
})

// -------------------------
// Edge cases
// -------------------------

test("out-of-order message delivery using skipped keys", async ({ page }) => {
    const result = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState0, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        let bobState = await TrustGramCrypto.acceptSession(
            bob, recipientBundle.oneTimePreKey, senderInfo.identityKey, senderInfo.ephemeralKey
        )

        // Alice sends 3 messages in order (same DH key, no reply from Bob)
        const { message: msg1, state: s1 } = await TrustGramCrypto.encryptMessage(aliceState0, "first")
        const { message: msg2, state: s2 } = await TrustGramCrypto.encryptMessage(s1, "second")
        const { message: msg3 } = await TrustGramCrypto.encryptMessage(s2, "third")

        // Bob receives msg2 first (out of order) — msg1 gets stored as skipped
        const { plaintext: plain2, state: bobState1 } = await TrustGramCrypto.decryptMessage(bobState, msg2)
        // Bob decrypts msg1 from the skipped keys store
        const { plaintext: plain1, state: bobState2 } = await TrustGramCrypto.decryptMessage(bobState1, msg1)
        // Bob decrypts msg3 normally
        const { plaintext: plain3 } = await TrustGramCrypto.decryptMessage(bobState2, msg3)

        return [plain1, plain2, plain3]
    })
    expect(result).toEqual(["first", "second", "third"])
})

test("too many skipped messages throws", async ({ page }) => {
    const error = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { state: aliceState0, senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        let bobState = await TrustGramCrypto.acceptSession(
            bob, recipientBundle.oneTimePreKey, senderInfo.identityKey, senderInfo.ephemeralKey
        )

        // Alice sends 102 messages; Bob only receives the last one (n=101, gap > MAX_SKIP=100)
        let aliceState = aliceState0
        let lastMessage: any
        for (let i = 0; i < 102; i++) {
            const { message, state } = await TrustGramCrypto.encryptMessage(aliceState, `msg ${i}`)
            aliceState = state
            lastMessage = message
        }

        try {
            await TrustGramCrypto.decryptMessage(bobState, lastMessage)
            return null
        } catch (e: any) {
            return e.message
        }
    })
    expect(error).toBe("Too many skipped messages")
})

test("acceptSession throws with unknown one-time pre-key", async ({ page }) => {
    const error = await page.evaluate(async () => {
        const alice = await TrustGramCrypto.createIdentity()
        const bob = await TrustGramCrypto.createIdentity()
        const alicePublicBundle = await TrustGramCrypto.getPublicBundle(alice)
        const bobPublicBundle = await TrustGramCrypto.getPublicBundle(bob)
        const recipientBundle = {
            identityKey: bobPublicBundle.identityKey,
            signedPreKey: bobPublicBundle.signedPreKey,
            oneTimePreKey: bobPublicBundle.oneTimePreKeys[0]
        }
        const { senderInfo } = await TrustGramCrypto.initiateSession(alice, recipientBundle)

        try {
            // Pass Alice's identity key as OPK — it won't match any of Bob's OPKs
            await TrustGramCrypto.acceptSession(
                bob,
                alicePublicBundle.identityKey,
                senderInfo.identityKey,
                senderInfo.ephemeralKey
            )
            return null
        } catch (e: any) {
            return e.message
        }
    })
    expect(error).toBe("One-time pre-key not found")
})
