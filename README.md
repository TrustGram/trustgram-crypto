# trustgram-crypto

End-to-end encryption library for [TrustGram](https://github.com/trustgram) — a zero-trust messenger built on top of Telegram.

Implements **X3DH + Double Ratchet** entirely in the browser using the Web Crypto API. No native dependencies, no server-side key material.

## How it fits in TrustGram

```
trustgram-ui  ──imports──▶  trustgram-crypto  (this repo)
                                    │
                            Web Crypto API
                            (browser built-in)

trustgram-bot  ──delivers──▶  encrypted blobs via Telegram
                               (never sees plaintext)
```

The bot and server are **zero-trust** — they only relay opaque ciphertext. All cryptographic operations happen client-side.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per message |
| Forward secrecy | Symmetric ratchet — past keys deleted after use |
| Break-in recovery | DH ratchet — new key pair on every reply |
| Asynchronous setup | X3DH — session starts without Bob being online |
| Out-of-order delivery | Skipped message keys stored up to 100 deep |
| MITM detection | Safety numbers (SHA-256 of both identity keys) |
| Key non-extractability | `extractable: false` in WebCrypto — private keys never leave the browser |

## API

```typescript
import {
    createIdentity,
    getPublicBundle,
    initiateSession,
    acceptSession,
    encryptMessage,
    decryptMessage,
    computeFingerprint
} from "./dist/crypto.js"

// --- First launch ---
const aliceIdentity = await createIdentity()
const alicePublic   = await getPublicBundle(aliceIdentity)  // publish to server

// --- Alice initiates session with Bob ---
const bobBundle = /* fetch from server */ { identityKey, signedPreKey, oneTimePreKey }
const { state: aliceState, senderInfo } = await initiateSession(aliceIdentity, bobBundle)
// send senderInfo to Bob via Telegram

// --- Bob accepts ---
const bobState = await acceptSession(
    bobIdentity,
    senderInfo.oneTimePreKeyId,
    senderInfo.identityKey,
    senderInfo.ephemeralKey
)

// --- Messaging ---
const { message, state: aliceState2 } = await encryptMessage(aliceState, "hello")
const { plaintext, state: bobState2 } = await decryptMessage(bobState, message)

// --- Safety numbers ---
const fp = await computeFingerprint(aliceIdentity, bobPublic.identityKey)
console.log(fp.display) // "1a2b 3c4d 5e6f ..."  — compare out-of-band
```

> **Important:** `RatchetState` is immutable. Always use the `state` returned from each call for the next operation.

## Build

```bash
npm install
npm run build        # outputs dist/crypto.js + dist/crypto.js.map
```

Bundled with [esbuild](https://esbuild.github.io/) — single ESM file, no module resolution issues in the browser.

## Test

```bash
npx playwright install chromium --with-deps   # first time only
npx playwright test
```

Tests run in a real Chromium browser to ensure Web Crypto API compatibility. Coverage is collected via V8 and reported by [monocart-reporter](https://github.com/cenfun/monocart-reporter).

| Metric | Coverage |
|---|---|
| Statements | 100% |
| Branches | 100% |
| Functions | 100% |
| Lines | 100% |

CI runs on every push to `main` via GitHub Actions. Coverage report is uploaded as an artifact.

## Verifying integrity

The build is hosted on Cloudflare Pages. `trustgram-ui` loads it via SRI hash to guarantee the code hasn't been tampered with:

```html
<script src="https://trustgram-crypto.pages.dev/dist/crypto.js" integrity="sha384-..."></script>
```

Verify manually:

```bash
curl https://trustgram-crypto.pages.dev/dist/crypto.js | openssl dgst -sha384 -binary | base64
```

## Documentation

Full documentation is available in the [Wiki](https://github.com/TrustGram/trustgram-crypto/wiki):

| Page | Description |
|---|---|
| [Getting Started](https://github.com/TrustGram/trustgram-crypto/wiki/Getting-Started) | Install, build, run tests |
| [API Reference](https://github.com/TrustGram/trustgram-crypto/wiki/API-Reference) | All public functions with examples |
| [Cryptography](https://github.com/TrustGram/trustgram-crypto/wiki/Cryptography) | X3DH + Double Ratchet in detail |
| [Security Model](https://github.com/TrustGram/trustgram-crypto/wiki/Security-Model) | Threat model, guarantees, limitations |
| [Development Guide](https://github.com/TrustGram/trustgram-crypto/wiki/Development-Guide) | File structure, adding tests, extending the library |
