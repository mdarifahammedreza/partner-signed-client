package partnersigned

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Expected values below were produced by the Node package (src/crypto.js) with the same inputs.
// These tests show the Go port is byte-for-byte compatible, not just self-consistent.
const (
	privateKeyPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICqluVmfy4RygW/w10w4mU2qd2RMl1m+VcGY+Ht/tenr\n-----END PRIVATE KEY-----\n"
	publicKeyPEM  = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAwUUCAZnYdD/YD/OKg74wzRbPfJtuA6nDknhqFnrxnz4=\n-----END PUBLIC KEY-----\n"

	nodeBody          = `{"partnerUserId":"USER_1","phoneNumber":"+8801712345678","name":"রেজা"}`
	nodeSigningString = "1700000000.req-123.afc0e72029cb181220d7ac92b6321c59ff563606d4fff55371d1eba4177bb1f9"
	nodeHMAC          = "v1=e5125595fc9ec8bc1c6dc3b0a7ec636b7cbd73fe532c1becd77469a3b571e032"
	nodeEd25519       = "v1=fw3pu56QonGoY/ID0IJNzZilLwqdKpHRA9HJXsekMQKtMcSMpbVK6E/63DQPmEHtz4jaFltGQAjtWaKh0G5AAg=="
)

func TestSigningStringMatchesNode(t *testing.T) {
	if got := BuildSigningString("1700000000", "req-123", []byte(nodeBody)); got != nodeSigningString {
		t.Fatalf("got %q, want %q", got, nodeSigningString)
	}
}

func TestSigningStringEmptyBody(t *testing.T) {
	want := "1.r.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := BuildSigningString("1", "r", nil); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestHMACMatchesNode(t *testing.T) {
	got, err := Sign(SchemeHMAC, nodeSigningString, "test-secret")
	if err != nil || got != nodeHMAC {
		t.Fatalf("got %q (%v), want %q", got, err, nodeHMAC)
	}
}

func TestEd25519MatchesNode(t *testing.T) {
	got, err := Sign(SchemeEd25519, nodeSigningString, privateKeyPEM)
	if err != nil || got != nodeEd25519 {
		t.Fatalf("got %q (%v), want %q", got, err, nodeEd25519)
	}
}

func TestSignRejectsUnknownSchemeAndBadKey(t *testing.T) {
	if _, err := Sign("rsa", nodeSigningString, "x"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("unknown scheme: got %v", err)
	}
	if _, err := Sign(SchemeEd25519, nodeSigningString, "not a pem"); err == nil {
		t.Fatal("bad PEM: expected an error")
	}
}

func TestVerifyAcceptsValidRejectsTampered(t *testing.T) {
	tampered := strings.Replace(nodeSigningString, "req-123", "req-124", 1)
	cases := []struct {
		name          string
		scheme        Scheme
		signingString string
		sig, key      string
		want          bool
	}{
		{"hmac valid", SchemeHMAC, nodeSigningString, nodeHMAC, "test-secret", true},
		{"ed25519 valid", SchemeEd25519, nodeSigningString, nodeEd25519, publicKeyPEM, true},
		{"hmac tampered", SchemeHMAC, tampered, nodeHMAC, "test-secret", false},
		{"ed25519 tampered", SchemeEd25519, tampered, nodeEd25519, publicKeyPEM, false},
		{"hmac wrong secret", SchemeHMAC, nodeSigningString, nodeHMAC, "wrong-secret", false},
		{"ed25519 wrong key", SchemeEd25519, nodeSigningString, nodeEd25519, otherPublicKeyPEM(t), false},
		{"ed25519 no prefix", SchemeEd25519, nodeSigningString, strings.TrimPrefix(nodeEd25519, "v1="), publicKeyPEM, false},
		{"unknown scheme", "rsa", nodeSigningString, nodeHMAC, "test-secret", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Verify(tc.scheme, tc.signingString, tc.sig, tc.key); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// otherPublicKeyPEM is a valid Ed25519 public key that did not produce nodeEd25519.
func otherPublicKeyPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestVerifierTimestampWindow(t *testing.T) {
	sentAt := time.Unix(1700000000, 0)
	at := func(d time.Duration) *Verifier {
		return &Verifier{Scheme: SchemeHMAC, Key: "test-secret", Now: func() time.Time { return sentAt.Add(d) }}
	}

	if err := at(299*time.Second).Verify("1700000000", "req-123", nodeHMAC, []byte(nodeBody)); err != nil {
		t.Fatalf("299s: got %v, want nil", err)
	}
	if err := at(-299*time.Second).Verify("1700000000", "req-123", nodeHMAC, []byte(nodeBody)); err != nil {
		t.Fatalf("-299s: got %v, want nil", err)
	}
	if err := at(301*time.Second).Verify("1700000000", "req-123", nodeHMAC, []byte(nodeBody)); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("301s: got %v, want ErrStaleTimestamp", err)
	}
	if err := at(0).Verify("1700000000", "req-123", nodeHMAC, []byte(nodeBody+" ")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered body: got %v, want ErrInvalidSignature", err)
	}
	if err := at(0).Verify("", "req-123", nodeHMAC, []byte(nodeBody)); !errors.Is(err, ErrMissingHeaders) {
		t.Fatalf("missing header: got %v, want ErrMissingHeaders", err)
	}
}

func TestMarshalBodyMatchesJSONStringify(t *testing.T) {
	got, err := MarshalBody(HandoffRequest{PartnerUserID: "USER_1", PhoneNumber: "+8801712345678", Name: "রেজা"})
	if err != nil || string(got) != nodeBody {
		t.Fatalf("got %q (%v), want %q", got, err, nodeBody)
	}
	// JSON.stringify leaves <, > and & alone; encoding/json would escape them by default.
	got, _ = MarshalBody(map[string]string{"a": "<b>&"})
	if string(got) != `{"a":"<b>&"}` {
		t.Fatalf("got %q", got)
	}
}

type captured struct {
	method, path string
	header       http.Header
	body         []byte
}

func captureServer(t *testing.T, status int, respBody string) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.method, c.path, c.header = r.Method, r.URL.Path, r.Header.Clone()
		c.body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func TestHandoffSendsNodeIdenticalBodyAndVerifiableHeaders(t *testing.T) {
	// Same shape as the live dev API's response (HTTP 201, envelope statusCode 200).
	const envelope = `{"status":true,"statusCode":200,"message":"Request successful","data":{"handoffCode":"hc_1","expiresIn":60,"entryUrl":"https://app.example/entry?code=hc_1","hasActiveSubscription":true},"path":"/api/v1/partner/auth/handoff","timestamp":"2026-01-01T00:00:00.000Z"}`

	for _, tc := range []struct {
		scheme            Scheme
		secret, verifyKey string
	}{
		{SchemeHMAC, "test-secret", "test-secret"},
		{SchemeEd25519, privateKeyPEM, publicKeyPEM},
	} {
		t.Run(string(tc.scheme), func(t *testing.T) {
			srv, got := captureServer(t, http.StatusCreated, envelope)

			resp, err := NewClient(srv.Client()).Handoff(context.Background(), HandoffOptions{
				BaseURL:       srv.URL + "/",
				Scheme:        tc.scheme,
				Secret:        tc.secret,
				PartnerID:     "partner-slug",
				PartnerUserID: "USER_1",
				PhoneNumber:   "+8801712345678",
				Name:          "রেজা",
				RequestID:     "req-123",
			})
			if err != nil {
				t.Fatal(err)
			}

			if got.method != http.MethodPost || got.path != "/api/v1/partner/auth/handoff" {
				t.Fatalf("sent %s %s", got.method, got.path)
			}
			if string(got.body) != nodeBody {
				t.Fatalf("body %q, want %q", got.body, nodeBody)
			}
			if ct := got.header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type %q", ct)
			}
			if id := got.header.Get(HeaderRequestID); id != "req-123" {
				t.Fatalf("X-Request-Id %q", id)
			}
			if pid := got.header.Get(HeaderPartnerID); pid != "partner-slug" {
				t.Fatalf("X-Partner-Id %q", pid)
			}
			v := &Verifier{Scheme: tc.scheme, Key: tc.verifyKey}
			if err := v.Verify(got.header.Get(HeaderTimestamp), got.header.Get(HeaderRequestID), got.header.Get(HeaderSignature), got.body); err != nil {
				t.Fatalf("receiver could not verify: %v", err)
			}

			if resp.Status != http.StatusCreated || !resp.OK || !resp.IsJSON() {
				t.Fatalf("status %d ok %v json %v", resp.Status, resp.OK, resp.IsJSON())
			}
			result, err := DataAs[HandoffResult](resp)
			if err != nil {
				t.Fatal(err)
			}
			if result.HandoffCode != "hc_1" || result.ExpiresIn != 60 || result.EntryURL == "" || !result.HasActiveSubscription {
				t.Fatalf("parsed %+v", result)
			}
			env, err := resp.Envelope()
			if err != nil || env.StatusCode != 200 || string(env.Status) != "true" || env.Message != "Request successful" {
				t.Fatalf("envelope %+v (%v)", env, err)
			}
		})
	}
}

func TestSignedRequestWithoutPartnerIDOmitsHeader(t *testing.T) {
	srv, got := captureServer(t, http.StatusOK, `{"ok":true}`)

	resp, err := NewClient(srv.Client()).SignedRequest(context.Background(), SignedRequestOptions{
		BaseURL: srv.URL,
		Path:    "deduct",
		Scheme:  SchemeHMAC,
		Secret:  "test-secret",
		Body:    map[string]string{"partnerUserId": "USER_1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got.header[HeaderPartnerID]; present {
		t.Fatal("X-Partner-Id must not be sent without a partner id")
	}
	if got.path != "/deduct" || got.header.Get(HeaderRequestID) == "" {
		t.Fatalf("path %q, request id %q", got.path, got.header.Get(HeaderRequestID))
	}
	// No "data" field: DecodeData falls back to the root object.
	var body struct{ OK bool }
	if err := resp.DecodeData(&body); err != nil || !body.OK {
		t.Fatalf("decoded %+v (%v)", body, err)
	}
}

func TestMiddleware(t *testing.T) {
	v := &Verifier{Scheme: SchemeHMAC, Key: "test-secret", Now: func() time.Time { return time.Unix(1700000000, 0) }}
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := RawBodyFromContext(r.Context())
		again, _ := io.ReadAll(r.Body)
		if string(raw) != nodeBody || string(again) != nodeBody {
			t.Errorf("handler saw %q / %q", raw, again)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	send := func(sig string) int {
		r := httptest.NewRequest(http.MethodPost, "/deduct", strings.NewReader(nodeBody))
		r.Header.Set(HeaderTimestamp, "1700000000")
		r.Header.Set(HeaderRequestID, "req-123")
		r.Header.Set(HeaderSignature, sig)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := send(nodeHMAC); code != http.StatusNoContent {
		t.Fatalf("valid: got %d", code)
	}
	if code := send("v1=00"); code != http.StatusUnauthorized {
		t.Fatalf("invalid: got %d", code)
	}
}
