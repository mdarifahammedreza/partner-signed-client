# danumai-partner-signed-client (Python)

Python port of the Node package in the repo root: the same **HMAC** and **Ed25519** partner
signed-request protocol, byte-for-byte compatible. The tests check it against signatures produced
by the Node `src/crypto.js`.

Requires Python 3.10+. Its only dependency is [`cryptography`](https://pypi.org/project/cryptography/)
(for Ed25519). HTTP uses the stdlib `urllib.request`, and you can plug in your own transport.

```
python/
├── pyproject.toml
├── src/partner_signed_client/
│   ├── crypto.py       # build_signing_string, sign_hmac, sign_ed25519, sign, verify   (= src/crypto.js)
│   ├── client.py       # signed_request, handoff, serialize_body, urllib_transport     (= src/client.js + src/handoff.js)
│   ├── verifier.py     # verify_request: receiving-side check for your own /deduct endpoint
│   └── models.py       # SignedResponse, HandoffResult, PreparedRequest, TransportResponse
├── examples/handoff_example.py   # = examples/test-handoff-{hmac,ed25519}.js
└── tests/test_compatibility.py
```

## Run

```sh
cd python
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest                                          # compatibility tests (offline)

# Uses the same repo-root .env as the Node examples (copy .env.example → .env)
python examples/handoff_example.py hmac
python examples/handoff_example.py ed25519
```

## Handoff flow

```python
import os
from partner_signed_client import HandoffResult, handoff

response = handoff(
    base_url="https://dev-api.banglareels.com",
    scheme="hmac",                              # or "ed25519"
    secret=os.environ["SIGNING_SECRET"],        # HMAC secret, or Ed25519 private key PEM
    partner_id="your-partner-slug",             # sent as X-Partner-Id
    partner_user_id="YOUR_USER_889123",
    phone_number="+8801712345678",
)

if response.ok:
    # The API wraps results as {status, statusCode, message, data}; .data unwraps `data`.
    result = HandoffResult.from_dict(response.data)
    # result.entry_url    → redirect the subscriber's browser here
    # result.handoff_code → single-use, ~60s TTL
```

`response` is a `SignedResponse` with `status`, `ok`, `headers` (lower-cased names), `raw_body`
(always the text), `json` (parsed when the response is JSON) and `data` (the envelope's `data`).
Non-2xx responses are returned, not raised.

For Ed25519, pass `scheme="ed25519"`. `secret` is then the PKCS#8 private key PEM
(`-----BEGIN PRIVATE KEY-----`). You can generate one with `openssl genpkey -algorithm ed25519`.
BanglaReels only ever stores your **public** key.

## Any other signed endpoint

```python
from partner_signed_client import signed_request

response = signed_request(
    base_url="https://dev-api.banglareels.com",
    path="/api/v1/partner/auth/merge-confirm",
    scheme="hmac",
    secret=secret,
    partner_id="your-partner-slug",   # leave out to simulate BanglaReels → your /deduct
    body={"partnerUserId": "YOUR_USER_889123"},
)
```

`body` is serialized like `JSON.stringify`: compact separators, no escaping of `+` or non-ASCII,
`None` fields left out, key order kept. So the Python client sends exactly the same bytes as the
Node client, and it signs those same bytes. A `str`/`bytes` body is sent as-is. One difference to
keep in mind: Python writes `1.0` where JavaScript writes `1`, so send money amounts as strings
(as the protocol already does).

To use `requests`/`httpx`, a proxy, or a test double, pass `transport=`. It's a callable that takes
a `PreparedRequest` (`method`, `url`, `headers`, `body` bytes, `timeout`) and returns a
`TransportResponse(status, headers, body_bytes)`.

## Verifying BanglaReels' calls to your `/deduct`

Verify against the **raw body bytes**. Read the body before any JSON parsing, because a
re-serialized copy won't hash the same. `verify_request` also enforces the ±300s timestamp window.

FastAPI:

```python
import json
from fastapi import FastAPI, HTTPException, Request
from partner_signed_client import verify_request

app = FastAPI()

@app.post("/deduct")
async def deduct(request: Request):
    raw_body = await request.body()          # exact bytes, before parsing

    if not verify_request(
        "hmac",
        OUTBOUND_SIGNING_SECRET,             # HMAC secret, or Ed25519 PUBLIC key PEM
        timestamp=request.headers.get("X-Timestamp"),
        request_id=request.headers.get("X-Request-Id"),
        signature=request.headers.get("X-Signature"),
        raw_body=raw_body,
    ):
        raise HTTPException(status_code=401)

    deduct = json.loads(raw_body)
    # dedupe on X-Request-Id / idempotencyKey, then charge...
    return {"ok": True}
```

Flask: the same, with `raw_body = request.get_data()` (call it before `request.json`).

The protocol itself is described in the root [README](../README.md#how-the-signature-is-built).
