# trustgram-crypto

TrustGram cryptographic engine — isolated crypto module.

## Purpose
All cryptographic primitives are isolated here for auditability.
Anyone can verify this code independently via browser DevTools (F12 → Sources).

## Stack
- Vanilla JS, zero dependencies
- Web Crypto API only (built-in browser primitives)
- Hosted on Cloudflare Pages

## Deploy
Production: https://trustgram-crypto.pages.dev/crypto.js

Automatic deployment on push to `main` via Cloudflare Pages.

## Usage
Include in trustgram-ui via SRI hash:
```html
<script src="https://trustgram-crypto.pages.dev/crypto.js" integrity="sha384-..."></script>
```

## Algorithms
- Key exchange: ECDH P-256
- Encryption: AES-256-GCM
- Key derivation: HKDF SHA-256

## Verifying integrity
```bash
curl https://trustgram-crypto.pages.dev/crypto.js | openssl dgst -sha384 -binary | base64
```
Compare the output with the `integrity` attribute in trustgram-ui `index.html`.
