// Package partnersigned is the Go port of the Node reference client for BanglaReels' Business
// Partner signed-request protocol. It supports both signing schemes, HMAC and Ed25519, and is
// byte-for-byte compatible with the Node package's src/crypto.js.
//
// It uses the standard library only.
package partnersigned

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Scheme is a signing scheme: SchemeHMAC or SchemeEd25519.
type Scheme string

const (
	// SchemeHMAC signs with hex(hmac_sha256(signingString, secret)).
	SchemeHMAC Scheme = "hmac"
	// SchemeEd25519 signs with base64(ed25519_sign(signingString, privateKey)).
	SchemeEd25519 Scheme = "ed25519"
)

// SignatureVersion is the prefix of every X-Signature value ("v1=...").
const SignatureVersion = "v1"

const signaturePrefix = SignatureVersion + "="

// ErrUnsupportedScheme is returned for any scheme other than "hmac" or "ed25519".
var ErrUnsupportedScheme = errors.New(`partnersigned: unsupported signing scheme, expected "hmac" or "ed25519"`)

// BuildSigningString binds the timestamp, request id and body together so that tampering with
// any one of them invalidates the signature:
//
//	{timestamp}.{requestId}.{hex(sha256(rawBody))}
//
// rawBody must be the exact bytes sent on the wire. Pass nil for a request without a body.
func BuildSigningString(timestamp, requestID string, rawBody []byte) string {
	sum := sha256.Sum256(rawBody)
	return timestamp + "." + requestID + "." + hex.EncodeToString(sum[:])
}

// SignHMAC returns "v1=" + hex(hmac_sha256(signingString, secret)).
func SignHMAC(signingString, secret string) string {
	return signaturePrefix + hmacHex(signingString, secret)
}

// SignEd25519 returns "v1=" + base64(ed25519_sign(signingString)). privateKeyPEM is a PKCS#8
// private key ("-----BEGIN PRIVATE KEY-----"), the format Node's crypto and
// `openssl genpkey -algorithm ed25519` produce.
func SignEd25519(signingString, privateKeyPEM string) (string, error) {
	key, err := ParseEd25519PrivateKey(privateKeyPEM)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, []byte(signingString))
	return signaturePrefix + base64.StdEncoding.EncodeToString(sig), nil
}

// Sign is the scheme-agnostic entry point. secret is the HMAC secret, or the Ed25519 private key
// PEM. It returns the already-prefixed ("v1=...") X-Signature value.
func Sign(scheme Scheme, signingString, secret string) (string, error) {
	switch scheme {
	case SchemeHMAC:
		return SignHMAC(signingString, secret), nil
	case SchemeEd25519:
		return SignEd25519(signingString, secret)
	default:
		return "", fmt.Errorf("%w (got %q)", ErrUnsupportedScheme, string(scheme))
	}
}

// Verify checks an X-Signature value against a signing string. key is the HMAC secret, or the
// sender's Ed25519 PUBLIC key PEM ("-----BEGIN PUBLIC KEY-----"). It returns false for any
// malformed input rather than an error.
//
// Verify does not check the timestamp window; use Verifier for a full receiving-side check.
func Verify(scheme Scheme, signingString, signatureHeader, key string) bool {
	switch scheme {
	case SchemeHMAC:
		// Constant-time comparison of the whole header value.
		expected := SignHMAC(signingString, key)
		return hmac.Equal([]byte(expected), []byte(signatureHeader))
	case SchemeEd25519:
		encoded, ok := strings.CutPrefix(signatureHeader, signaturePrefix)
		if !ok {
			return false
		}
		sig, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return false
		}
		pub, err := ParseEd25519PublicKey(key)
		if err != nil {
			return false
		}
		return ed25519.Verify(pub, []byte(signingString), sig)
	default:
		return false
	}
}

// ParseEd25519PrivateKey parses a PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----") Ed25519 private key.
func ParseEd25519PrivateKey(privateKeyPEM string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("partnersigned: Ed25519 private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("partnersigned: parsing Ed25519 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("partnersigned: private key is %T, not Ed25519", parsed)
	}
	return key, nil
}

// ParseEd25519PublicKey parses an SPKI PEM ("-----BEGIN PUBLIC KEY-----") Ed25519 public key.
func ParseEd25519PublicKey(publicKeyPEM string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("partnersigned: Ed25519 public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("partnersigned: parsing Ed25519 public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("partnersigned: public key is %T, not Ed25519", parsed)
	}
	return key, nil
}

func hmacHex(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
