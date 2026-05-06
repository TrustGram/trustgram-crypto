# Technical Reference — trustgram-crypto

This document is for contributors and maintainers. It covers the cryptographic protocols in detail, the code structure, and guidance for extending the library.

---

## Table of Contents

1. [Repository structure](#repository-structure)
2. [Cryptographic stack](#cryptographic-stack)
3. [X3DH protocol](#x3dh-protocol)
4. [Double Ratchet](#double-ratchet)
5. [Key storage](#key-storage)
6. [Build pipeline](#build-pipeline)
7. [Testing](#testing)
8. [Security considerations](#security-considerations)
9. [Extending the library](#extending-the-library)

---

## Repository structure

```
src/
  types.ts       — TypeScript interfaces (wire types, ratchet state, fingerprint)
  primitives.ts  — Web Crypto API wrappers (ECDH, HKDF, AES-GCM, SHA-256)
  x3dh.ts        — X3DH key agreement (session establishment)
  ratchet.ts     — Double Ratchet (per-message encryption)
  index.ts       — Public API (the only file trustgram-ui imports)

tests/
  crypto.test.ts — 18 Playwright tests, 100% coverage
  test.html      — minimal HTML page that loads dist/crypto.js for browser tests

dist/            — built output (gitignored)
  crypto.js      — bundled ESM module
  crypto.js.map  — source map

docs/
  TECHNICAL.md   — this file

.github/
  workflows/test.yml — CI: build → test → upload coverage artifact
```

**Dependency rule:** `index.ts` → `x3dh.ts` + `ratchet.ts` → `primitives.ts` → Web Crypto API. No circular imports. `types.ts` is imported by everyone, exports nothing runtime.

---

## Cryptographic stack

| Layer | Algorithm | Implementation |
|---|---|---|
| Key exchange | ECDH P-256 | `crypto.subtle.deriveBits` |
| Key derivation | HKDF-SHA-256 | `crypto.subtle.deriveBits` with HKDF |
| Symmetric encryption | AES-256-GCM | `crypto.subtle.encrypt` / `decrypt` |
| Hashing | SHA-256 | `crypto.subtle.digest` |

Everything runs inside the browser's native Web Crypto API — no third-party crypto libraries. This makes the code auditable: anyone can open DevTools and verify the implementation matches the source.

---

## X3DH protocol

X3DH (Extended Triple Diffie-Hellman) establishes a shared secret between Alice and Bob without requiring both to be online simultaneously.

### Key roles

| Key | Name | Lifetime |
|---|---|---|
| IK | Identity Key | Permanent (per identity) |
| SPK | Signed Pre-Key | Rotated periodically |
| OPK | One-Time Pre-Key | Consumed once per session |
| EK | Ephemeral Key | Generated fresh by Alice per session |

### Key publication (Bob)

On first launch Bob generates:
- 1 IK (long-term identity)
- 1 SPK (medium-term, should be rotated)
- 10 OPKs (single-use, server removes after delivery)

He publishes the public halves to the server (`getPublicBundle`).

### Session initiation (Alice)

Alice fetches Bob's public bundle from the server. She performs 4 ECDH operations:

```
DH1 = ECDH(IK_A.priv,  SPK_B.pub)   — authenticates Alice to Bob
DH2 = ECDH(EK_A.priv,  IK_B.pub)    — authenticates Bob to Alice
DH3 = ECDH(EK_A.priv,  SPK_B.pub)   — ephemeral-to-signed binding
DH4 = ECDH(EK_A.priv,  OPK_B.pub)   — one-time forward secrecy

masterSecret = HKDF(DH1 || DH2 || DH3 || DH4, salt=0x00…, info="TrustGram_X3DH_v1")
```

Alice sends Bob: `{ IK_A.pub, EK_A.pub, OPK_B.pub }` (the `senderInfo` struct).

### Session acceptance (Bob)

Bob mirrors Alice's 4 operations using his private keys:

```
DH1 = ECDH(SPK_B.priv, IK_A.pub)
DH2 = ECDH(IK_B.priv,  EK_A.pub)
DH3 = ECDH(SPK_B.priv, EK_A.pub)
DH4 = ECDH(OPK_B.priv, EK_A.pub)

masterSecret = HKDF(DH1 || DH2 || DH3 || DH4, …)  — same result as Alice
```

ECDH is commutative: `ECDH(a, B) = ECDH(b, A)`, so both sides arrive at identical DH outputs.

### Implementation files

- `src/x3dh.ts` — `x3dhSend`, `x3dhReceive`, `combineDH`
- `src/index.ts` — `initiateSession`, `acceptSession`

---

## Double Ratchet

The Double Ratchet runs on top of the X3DH master secret. It provides per-message keys with forward secrecy and break-in recovery.

### Two ratchets

**Symmetric-key ratchet (chain ratchet)**

A chain key is hashed twice per message — once to produce the message key, once to advance the chain:

```
messageKey  = HKDF(chainKey, salt, "TrustGram_MessageKey_v1")
chainKey    = HKDF(chainKey, salt, "TrustGram_ChainKey_v1")
```

Message keys are deleted after use. Past messages cannot be decrypted even if the current state is compromised.

**Diffie-Hellman ratchet**

On every reply, the receiver generates a fresh DH key pair. The sender sees it in the next message header and performs a DH ratchet step:

```
(rootKey, recvChainKey) = HKDF_expand(rootKey, ECDH(dhSend.priv, theirDH.pub))
newDhSend = generateKeyPair()
(rootKey, sendChainKey) = HKDF_expand(rootKey, ECDH(newDhSend.priv, theirDH.pub))
```

This injects fresh entropy into the chain keys after every round-trip, providing break-in recovery.

### Initialization asymmetry

Alice and Bob start from different initial states:

| | Alice (`initSenderRatchet`) | Bob (`initReceiverRatchet`) |
|---|---|---|
| `dhSendKey` | fresh random key pair | Bob's SPK |
| `dhRecvKey` | Bob's SPK public key | null |
| `sendChainKey` | derived immediately | null (set on first decrypt) |

This asymmetry is intentional: Alice's first `ECDH(aliceDH, bobSPK)` must equal Bob's `ECDH(bobSPK, aliceDH)`, so Bob must start with his SPK as the initial DH key.

### Message header

Every encrypted message carries:

```typescript
{
    dhPub: string   // sender's current DH public key (base64)
    n: number       // message index in current chain
    pn: number      // message count in previous chain
    iv: string      // AES-GCM nonce (base64)
    ciphertext: string  // AES-256-GCM output including auth tag (base64)
}
```

`pn` tells the receiver how many messages were in the sender's previous chain, which is needed to correctly skip keys when a DH ratchet step occurs.

### Out-of-order delivery

When a later message arrives before an earlier one, the receiver derives and stores the skipped message keys:

```
skippedKeys.push({ dhKey, n, messageKey })
```

When the earlier message eventually arrives, its key is looked up by `(dhKey, n)` and used directly without re-deriving. Stored up to `MAX_SKIP = 100` keys to prevent memory exhaustion.

### Implementation files

- `src/ratchet.ts` — `initSenderRatchet`, `initReceiverRatchet`, `ratchetEncrypt`, `ratchetDecrypt`, `dhRatchetStep`, `advanceChain`, `skipMessageKeys`

---

## Key storage

Private keys are generated with `extractable: false`:

```typescript
crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [...])
```

This means JavaScript code can never read the raw private key bytes — the key lives inside the browser's WebCrypto subsystem. Even if an attacker injects JS into the page, they cannot exfiltrate the private key directly.

**Persistence:** `IdentityKeyBundle` (containing `CryptoKey` objects) should be stored in IndexedDB. IndexedDB supports `CryptoKey` values natively — the browser serializes and restores them while preserving the non-extractable property.

> **Not yet implemented:** The current MVP stores identity in memory only. IndexedDB persistence is a planned feature.

---

## Build pipeline

```
src/*.ts  ──esbuild──▶  dist/crypto.js  (ESM, bundled, sourcemapped)
```

Single-file output eliminates ES module resolution issues in browser tests (Chromium blocks `import` over `file://`). The `webServer` in `playwright.config.ts` serves the repo over HTTP during tests.

Build command:
```bash
npm run build
# esbuild src/index.ts --bundle --format=esm --sourcemap --outfile=dist/crypto.js
```

---

## Testing

Tests run in a real Chromium browser via Playwright — this is required because the implementation uses `window.crypto.subtle`, which is not available in Node.js.

### Test setup

`tests/test.html` loads `dist/crypto.js` as an ES module and sets `window.__cryptoReady = true`. Each test waits for this flag before evaluating crypto operations via `page.evaluate`.

### Coverage collection

V8 coverage is collected via `page.coverage.startJSCoverage()` / `stopJSCoverage()` and aggregated by `monocart-reporter`. The `entryFilter` in `playwright.config.ts` limits coverage to `dist/crypto.js`; `sourceFilter` maps it back to `src/` via the source map.

### Test cases

| Category | Tests |
|---|---|
| Identity & keys | createIdentity, getPublicBundle, unique keys |
| Encryption | round-trip, multiple messages, bidirectional, empty string, long message |
| Security | unique ciphertext, tampered ciphertext, wrong key, two independent sessions |
| Edge cases | out-of-order delivery, MAX\_SKIP exceeded, unknown OPK |
| Fingerprint | same for both parties, differs per pair, display format |

---

## Security considerations

**What the server sees:** Only encrypted `EncryptedMessage` blobs, `senderInfo` (Alice's public keys), and user identifiers. No plaintext, no private keys.

**What Telegram sees:** The same encrypted blobs delivered as messages. Telegram acts as an untrusted transport layer.

**MITM attack:** Possible if the server substitutes Bob's public keys with the attacker's. Mitigated by safety numbers (`computeFingerprint`) — users compare a SHA-256-derived display string out-of-band.

**Key compromise:** Compromising Alice's current `RatchetState` exposes only messages encrypted with the current chain key. The DH ratchet ensures future messages use fresh key material. Past messages are unrecoverable (forward secrecy).

**OPK exhaustion:** If Bob's OPKs are exhausted, the server must fall back to SPK only (DH4 omitted). This is not yet implemented — the current code always requires an OPK.

**SPK rotation:** Not yet implemented. SPKs should be rotated periodically (e.g. weekly) and signed with IK to prevent substitution.

---

## Extending the library

### Adding a new primitive

Add to `src/primitives.ts`. Keep functions pure (input → output, no side effects). Export from `primitives.ts` only — do not add to `index.ts` unless it belongs to the public API.

### Changing the wire format (`EncryptedMessage`)

Bump the version string in the HKDF info labels (`TrustGram_X3DH_v1`, `TrustGram_Ratchet_v1`, etc.) to ensure old and new sessions are cryptographically incompatible and cannot accidentally interoperate.

### Adding a test

Tests live in `tests/crypto.test.ts`. All test logic runs inside `page.evaluate(async () => { ... })` — the callback executes in the browser context where `window.TrustGramCrypto` is available. Return plain JSON-serializable values from `page.evaluate` (no `CryptoKey` objects).

### CI

GitHub Actions runs on every push to `main`:
1. `npm install`
2. `npm run build`
3. `npx playwright install chromium --with-deps`
4. `npx playwright test`
5. Upload `coverage/` as artifact
