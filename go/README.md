# partnersigned (Go)

Go port of the Node package in the repo root: the same **HMAC** and **Ed25519** partner
signed-request protocol, byte-for-byte compatible. The tests check it against signatures produced
by the Node `src/crypto.js`.

Requires Go 1.21+. Standard library only (`crypto/ed25519`, `crypto/x509`, `encoding/pem`,
`net/http`), no third-party dependencies.

```
go/
├── go.mod                   # module github.com/mdarifahammedreza/partner-signed-client/go
├── crypto.go                # BuildSigningString, SignHMAC, SignEd25519, Sign, Verify   (= src/crypto.js)
├── client.go                # Client.SignedRequest, Client.Handoff, MarshalBody        (= src/client.js + src/handoff.js)
├── verifier.go              # Verifier + net/http Middleware for your own /deduct endpoint
├── models.go                # options, HandoffRequest/HandoffResult, Envelope, Response
├── partnersigned_test.go    # compatibility tests (offline)
└── examples/handoff/        # = examples/test-handoff-{hmac,ed25519}.js
```

## Install

```sh
go get github.com/mdarifahammedreza/partner-signed-client/go
```

```go
import partnersigned "github.com/mdarifahammedreza/partner-signed-client/go"
```

## Run

```sh
cd go
go test ./...                          # compatibility tests (offline)

# Uses the same repo-root .env as the Node examples (copy .env.example → .env)
go run ./examples/handoff hmac
go run ./examples/handoff ed25519
```

## Handoff flow

```go
client := partnersigned.NewClient(&http.Client{Timeout: 10 * time.Second}) // or &partnersigned.Client{}

resp, err := client.Handoff(ctx, partnersigned.HandoffOptions{
	BaseURL:       "https://dev-api.banglareels.com",
	Scheme:        partnersigned.SchemeHMAC,  // or partnersigned.SchemeEd25519
	Secret:        os.Getenv("SIGNING_SECRET"), // HMAC secret, or Ed25519 private key PEM
	PartnerID:     "your-partner-slug",         // sent as X-Partner-Id
	PartnerUserID: "YOUR_USER_889123",
	PhoneNumber:   "+8801712345678",
})
if err != nil {
	return err // transport or signing error; HTTP error statuses are not errors
}

if resp.OK {
	// The API wraps results as {status, statusCode, message, data}. DataAs unwraps `data`.
	result, err := partnersigned.DataAs[partnersigned.HandoffResult](resp)
	if err != nil {
		return err
	}
	// result.EntryURL    → redirect the subscriber's browser here
	// result.HandoffCode → single-use, ~60s TTL
}
```

`resp` has `Status`, `OK`, `Headers` and `RawBody`. `resp.DecodeData(&v)` is the non-generic
form of `DataAs`, `resp.Envelope()` returns the envelope itself (for `message` on errors), and
`resp.Decode(&v)` decodes the whole body.

For Ed25519, set `Scheme: partnersigned.SchemeEd25519`. `Secret` is then the PKCS#8 private key
PEM (`-----BEGIN PRIVATE KEY-----`). You can generate one with Node, or with
`openssl genpkey -algorithm ed25519`.

## Any other signed endpoint

```go
resp, err := client.SignedRequest(ctx, partnersigned.SignedRequestOptions{
	BaseURL:   "https://dev-api.banglareels.com",
	Path:      "/api/v1/partner/auth/merge-confirm",
	Scheme:    partnersigned.SchemeHMAC,
	Secret:    secret,
	PartnerID: "your-partner-slug", // leave empty to simulate BanglaReels → your /deduct
	Body:      map[string]string{"partnerUserId": "YOUR_USER_889123"},
})
```

`Method` defaults to `POST`, `RequestID` to a random UUID (reuse it on retries of the same
attempt), and `ExtraHeaders` are added last.

`Body` is serialized by `MarshalBody` to match `JSON.stringify`: `<`, `>` and `&` are not escaped,
non-ASCII (e.g. Bangla names) stays raw UTF-8, and there is no trailing newline. Plain
`json.Marshal` escapes those characters, and `json.Encoder` adds a newline, and either would
change the body hash. Use struct tags with `omitempty` for optional fields, because
`JSON.stringify` leaves `undefined` fields out. Struct fields are written in declaration order, so
declare them in the same order the Node client uses. One edge case differs: Go always escapes
U+2028 and U+2029 as ` `/` `, where `JSON.stringify` writes them raw. This only matters
if a body contains those characters.

## Verifying BanglaReels' calls to your `/deduct` (net/http)

Sign and verify against the **raw body bytes**. Read the body before decoding it, because a
re-serialized copy won't hash the same.

```go
verifier := &partnersigned.Verifier{
	Scheme: partnersigned.SchemeHMAC,
	Key:    outboundSigningSecret, // HMAC secret, or the Ed25519 PUBLIC key PEM
}

http.HandleFunc("/deduct", func(w http.ResponseWriter, r *http.Request) {
	// Reads the body, checks the ±300s timestamp window, then the signature.
	rawBody, err := verifier.VerifyRequest(r)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var deduct DeductRequest
	if err := json.Unmarshal(rawBody, &deduct); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	// dedupe on X-Request-Id / idempotencyKey, then charge...
	w.WriteHeader(http.StatusOK)
})
```

Or wrap a handler with the middleware, which answers 401 for requests that fail verification:

```go
http.Handle("/deduct", verifier.Middleware(deductHandler))
// inside deductHandler: rawBody, _ := partnersigned.RawBodyFromContext(r.Context())
// (r.Body can also still be read)
```

`Verifier.Verify(timestamp, requestID, signature, rawBody)` does the same check when you already
have the headers and body. The errors are `ErrMissingHeaders`, `ErrInvalidTimestamp`,
`ErrStaleTimestamp` and `ErrInvalidSignature`. `Tolerance` (default 300s), `Now` and
`MaxBodyBytes` (default 1 MiB) can be overridden.

The protocol itself is described in the root [README](../README.md#how-the-signature-is-built).
