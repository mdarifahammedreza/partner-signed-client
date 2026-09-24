package partnersigned

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

// DefaultTolerance is the allowed clock skew between sender and receiver (±300s).
const DefaultTolerance = 300 * time.Second

// DefaultMaxBodyBytes caps how much of a request body Verifier.VerifyRequest reads.
const DefaultMaxBodyBytes int64 = 1 << 20

// Errors returned by Verifier.
var (
	ErrMissingHeaders   = errors.New("partnersigned: missing X-Timestamp, X-Request-Id or X-Signature")
	ErrInvalidTimestamp = errors.New("partnersigned: X-Timestamp is not a Unix timestamp")
	ErrStaleTimestamp   = errors.New("partnersigned: X-Timestamp is outside the allowed window")
	ErrInvalidSignature = errors.New("partnersigned: signature does not match")
)

// Verifier is the receiving-side check for a signed request. Use it in your own /deduct endpoint
// to validate what BanglaReels sends you. It mirrors the backend's PartnerSignatureGuard: first the
// timestamp window, then the signature over the exact raw body.
type Verifier struct {
	// Scheme is SchemeHMAC or SchemeEd25519.
	Scheme Scheme
	// Key is the HMAC secret, or the sender's Ed25519 PUBLIC key PEM.
	Key string
	// Tolerance is the allowed clock skew. Zero means DefaultTolerance.
	Tolerance time.Duration
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// MaxBodyBytes caps the body VerifyRequest reads. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Verify checks the three signature headers against rawBody, which must be the request body
// exactly as received. It returns nil when the request is valid.
func (v *Verifier) Verify(timestamp, requestID, signature string, rawBody []byte) error {
	if timestamp == "" || requestID == "" || signature == "" {
		return ErrMissingHeaders
	}
	sentAt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	tolerance := v.Tolerance
	if tolerance == 0 {
		tolerance = DefaultTolerance
	}
	skew := now().Unix() - sentAt
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(tolerance/time.Second) {
		return ErrStaleTimestamp
	}

	if !Verify(v.Scheme, BuildSigningString(timestamp, requestID, rawBody), signature, v.Key) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyRequest reads r.Body, verifies it together with the X-Timestamp, X-Request-Id and
// X-Signature headers, and returns the raw body so you can decode it afterwards. r.Body is
// replaced with a fresh reader over the same bytes.
func (v *Verifier) VerifyRequest(r *http.Request) ([]byte, error) {
	limit := v.MaxBodyBytes
	if limit == 0 {
		limit = DefaultMaxBodyBytes
	}

	var rawBody []byte
	if r.Body != nil {
		var err error
		rawBody, err = io.ReadAll(io.LimitReader(r.Body, limit))
		r.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(rawBody))

	err := v.Verify(
		r.Header.Get(HeaderTimestamp),
		r.Header.Get(HeaderRequestID),
		r.Header.Get(HeaderSignature),
		rawBody,
	)
	if err != nil {
		return nil, err
	}
	return rawBody, nil
}

type rawBodyKey struct{}

// Middleware rejects requests that fail VerifyRequest with 401 Unauthorized. For requests that
// pass, the raw body is available both as r.Body and via RawBodyFromContext.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := v.VerifyRequest(r)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), rawBodyKey{}, rawBody)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RawBodyFromContext returns the verified raw body stored by Verifier.Middleware.
func RawBodyFromContext(ctx context.Context) ([]byte, bool) {
	b, ok := ctx.Value(rawBodyKey{}).([]byte)
	return b, ok
}
