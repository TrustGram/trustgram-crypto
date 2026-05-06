import { test, expect, chromium } from "@playwright/test"
import path from "path"

// Load dist files in a real browser context
test.beforeEach(async ({ page }) => {
    await page.goto(`file://${path.resolve("dist/test.html")}`)
})

test("generateKeyPair returns a key pair", async ({ page }) => {
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

        // Alice initiates session
        const { state: aliceState } = await TrustGramCrypto.initiateSession(alice, recipientBundle)

        // Alice encrypts
        const { message, state: aliceState2 } = await TrustGramCrypto.encryptMessage(aliceState, "hello bob")

        // Bob accepts session
        const bobState = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            (await TrustGramCrypto.getPublicBundle(alice)).identityKey,
            message.dhPub
        )

        // Bob decrypts
        const { plaintext } = await TrustGramCrypto.decryptMessage(bobState, message)
        return plaintext
    })
    expect(plaintext).toBe("hello bob")
})

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

        const { state: aliceState } = await TrustGramCrypto.initiateSession(alice, recipientBundle)
        const { message } = await TrustGramCrypto.encryptMessage(aliceState, "secret")

        // Tamper with ciphertext
        const tampered = { ...message, ciphertext: message.ciphertext.slice(0, -4) + "AAAA" }

        const bobState = await TrustGramCrypto.acceptSession(
            bob,
            recipientBundle.oneTimePreKey,
            (await TrustGramCrypto.getPublicBundle(alice)).identityKey,
            message.dhPub
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
