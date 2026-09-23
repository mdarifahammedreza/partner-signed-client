# @danumai/partner-signed-client

Reference client for BanglaReels' **Business Partner** signed-request protocol. One universal
function handles both supported signing schemes — **HMAC** and **Ed25519** — for calling BanglaReels'
partner-signed endpoints (e.g. the WebView handoff flow) and for simulating BanglaReels' own
outbound calls to your `/deduct` endpoint.

Zero runtime dependencies. Requires Node.js 18+ (uses the built-in `fetch` and `crypto`).

## Install

```sh
npm install @danumai/partner-signed-client
```

## The two directions

This protocol is used in two directions, and they don't use quite the same headers:

1. **Your backend calls BanglaReels** (e.g. `POST partner/auth/handoff` to mint a WebView entry
   code for a subscriber). You sign the request with the credential BanglaReels issued you, and
   include your partner slug as `X-Partner-Id`.
2. **BanglaReels calls your `/deduct` endpoint** (outbound, pay-per-content and subscription
   purchases/renewals). BanglaReels signs the request the same way, but never sends `X-Partner-Id`
   — your endpoint already knows who it is. Use this package to build a test double for your own
   `/deduct` implementation, or to independently verify a signature you received.

## Quick start — handoff flow

The most common integration: mint a short-lived WebView entry code for a subscriber.

```js
const { handoff } = require('@danumai/partner-signed-client');

const result = await handoff({
  baseUrl: 'https://dev-api.banglareels.com',
  scheme: 'hmac',                 // or 'ed25519'
  secret: process.env.SIGNING_SECRET,   // HMAC secret, or Ed25519 private key PEM
  partnerId: 'your-partner-slug',       // sent as X-Partner-Id
  partnerUserId: 'YOUR_USER_889123',    // your own user id; must match what you'll later send on payment callbacks
  phoneNumber: '+8801712345678',        // E.164 preferred
});

console.log(result.status);              // 200/201 on success
console.log(result.body.entryUrl);       // redirect the subscriber's browser here
console.log(result.body.handoffCode);    // single-use, ~60s TTL
```

`handoff()` builds the request to `POST {baseUrl}/api/v1/partner/auth/handoff`, signs it, and
returns the parsed response — this is the actual "handoff first, get a response back" flow, not
just a raw HTTP call.

### Ed25519 instead of HMAC

Identical call shape — only `scheme` and `secret` change. `secret` is your Ed25519 **private key**
in PEM format:

```js
const result = await handoff({
  baseUrl: 'https://dev-api.banglareels.com',
  scheme: 'ed25519',
  secret: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIP...
-----END PRIVATE KEY-----`,
  partnerId: 'your-partner-slug',
  partnerUserId: 'YOUR_USER_889123',
  phoneNumber: '+8801712345678',
});
```

BanglaReels only ever stores your **public** key — generate the keypair yourself and send us the
public key when we set up your credential; never share the private key with us or anyone else.

## Calling any other partner-signed endpoint

`signedRequest()` is the lower-level, general-purpose function `handoff()` is built on:

```js
const { signedRequest } = require('@danumai/partner-signed-client');

const result = await signedRequest({
  baseUrl: 'https://dev-api.banglareels.com',
  path: '/api/v1/partner/auth/merge-confirm',
  method: 'POST',
  scheme: 'hmac',
  secret: process.env.SIGNING_SECRET,
  partnerId: 'your-partner-slug',
  body: { partnerUserId: 'YOUR_USER_889123' },
});
```

Simulating BanglaReels calling *your* `/deduct` endpoint (no `partnerId`):

```js
const result = await signedRequest({
  baseUrl: 'https://your-partner-api.example.com',
  path: '/deduct',
  method: 'POST',
  scheme: 'hmac',
  secret: '<the outbound signing secret BanglaReels was given for your credential>',
  body: {
    partnerUserId: 'YOUR_USER_889123',
    idempotencyKey: 'some-uuid',
    amount: '100.00',
    currencyCode: 'BDT',
    purpose: 'subscription_purchase',
  },
});
```

## How the signature is built

If you're implementing your own client in another language (e.g. to build your `/deduct`
verifier), the protocol is:

1. `timestamp` — Unix seconds, must be within ±300s of server time.
2. `requestId` — a UUID (or any unique string); reuse the same value across retries of the same
   attempt so the receiving side can dedupe.
3. `bodyHash = sha256(rawRequestBody)` — hex-encoded. Sign/verify against the **exact bytes sent**,
   not a re-serialized copy (different key ordering changes the hash).
4. `signingString = ${timestamp}.${requestId}.${bodyHash}`
5. Signature:
   - **HMAC**: `hex(hmac_sha256(signingString, secret))`, prefixed `v1=`.
   - **Ed25519**: `base64(ed25519_sign(signingString, privateKey))`, prefixed `v1=`.
6. Headers sent with the request: `X-Request-Id`, `X-Timestamp`, `X-Signature`, and `X-Partner-Id`
   (only on the into-BanglaReels direction).

## API reference

### `handoff(options)`

| Option | Required | Description |
|---|---|---|
| `baseUrl` | yes | e.g. `https://dev-api.banglareels.com` |
| `apiPrefix` | no | default `/api/v1` |
| `scheme` | yes | `'hmac'` \| `'ed25519'` |
| `secret` | yes | HMAC secret, or Ed25519 private key PEM |
| `partnerId` | yes | your partner slug (`X-Partner-Id`) |
| `partnerUserId` | yes | your own user id |
| `phoneNumber` | yes | E.164 preferred |
| `name`, `email`, `returnPath` | no | optional |
| `requestId` | no | auto-generated (UUID) if omitted |

Returns `{ status, ok, headers, body }` where `body` is the parsed
`{ handoffCode, expiresIn, entryUrl, hasActiveSubscription, pendingMerge? }` on success.

### `signedRequest(options)`

| Option | Required | Description |
|---|---|---|
| `baseUrl`, `path` | yes | target URL parts |
| `method` | no | default `POST` |
| `body` | no | sent as JSON |
| `scheme`, `secret` | yes | as above |
| `partnerId` | no | omit for the outbound (BanglaReels→you) direction |
| `requestId` | no | auto-generated if omitted |
| `extraHeaders` | no | additional headers |

### `sign(scheme, signingString, secret)`, `signHmac`, `signEd25519`, `buildSigningString`

Lower-level building blocks, exported in case you need to construct a signature without making
the HTTP call yourself (e.g. inside your own `/deduct` request verifier).

## Security

- Never commit real secrets. Copy `.env.example` to `.env` (already git-ignored) for local testing.
- Ed25519 is preferred over HMAC where you can choose — BanglaReels never sees your private key at
  all, only the public key you register.
- `requestId` should be unique per *attempt*, not per retry of that attempt — reusing it on retry is
  what makes the receiving side idempotent instead of double-processing.

## License

UNLICENSED — internal/authorized-partner use only. Contact BanglaReels for access.
