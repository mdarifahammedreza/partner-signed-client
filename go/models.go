package partnersigned

import (
	"encoding/json"
	"net/http"
)

// Header names used by the protocol.
const (
	HeaderRequestID = "X-Request-Id"
	HeaderTimestamp = "X-Timestamp"
	HeaderSignature = "X-Signature"
	HeaderPartnerID = "X-Partner-Id"
)

// DefaultAPIPrefix is the API prefix Handoff uses when HandoffOptions.APIPrefix is empty.
const DefaultAPIPrefix = "/api/v1"

// SignedRequestOptions configures Client.SignedRequest.
type SignedRequestOptions struct {
	// BaseURL, e.g. "https://dev-api.banglareels.com" or a partner's own API base. Required.
	BaseURL string
	// Path, e.g. "/api/v1/partner/auth/merge-confirm". Required.
	Path string
	// Method defaults to POST.
	Method string
	// Body is serialized to JSON the way JSON.stringify would (see MarshalBody). Nil means no body.
	Body any
	// Scheme is SchemeHMAC or SchemeEd25519. Required.
	Scheme Scheme
	// Secret is the HMAC secret, or the Ed25519 private key PEM. Required.
	Secret string
	// PartnerID is sent as X-Partner-Id. Leave empty for the outbound (BanglaReels to partner)
	// direction, which never sends it.
	PartnerID string
	// RequestID is sent as X-Request-Id. Reuse the same value on every retry of one attempt.
	// A random UUID is generated when empty.
	RequestID string
	// ExtraHeaders are set after the protocol headers.
	ExtraHeaders map[string]string
}

// HandoffOptions configures Client.Handoff.
type HandoffOptions struct {
	// BaseURL, e.g. "https://dev-api.banglareels.com". Required.
	BaseURL string
	// APIPrefix defaults to "/api/v1".
	APIPrefix string
	// Scheme is SchemeHMAC or SchemeEd25519. Required.
	Scheme Scheme
	// Secret is the HMAC secret, or the Ed25519 private key PEM. Required.
	Secret string
	// PartnerID is your partner slug (X-Partner-Id). Required.
	PartnerID string
	// PartnerUserID is your own user id; it must match what you later send on payment callbacks.
	PartnerUserID string
	// PhoneNumber, E.164 preferred. Required.
	PhoneNumber string
	// Optional fields; left out of the body when empty.
	Name       string
	Email      string
	ReturnPath string
	// RequestID is generated when empty.
	RequestID string
}

// HandoffRequest is the body of POST partner/auth/handoff. It matches PartnerHandoffDto, with the
// same field order as the Node client.
type HandoffRequest struct {
	PartnerUserID string `json:"partnerUserId"`
	PhoneNumber   string `json:"phoneNumber"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	ReturnPath    string `json:"returnPath,omitempty"`
}

// HandoffResult is the payload of a successful handoff, found in the envelope's "data" field.
type HandoffResult struct {
	HandoffCode           string          `json:"handoffCode"`
	ExpiresIn             int             `json:"expiresIn"`
	EntryURL              string          `json:"entryUrl"`
	HasActiveSubscription bool            `json:"hasActiveSubscription"`
	PendingMerge          json.RawMessage `json:"pendingMerge,omitempty"`
}

// Envelope is the wrapper BanglaReels puts around API results, e.g.
//
//	{"status":true,"statusCode":200,"message":"Request successful","data":{...},"path":"...","timestamp":"..."}
//
// Status is kept raw because its JSON type is not guaranteed (true on success). StatusCode is the
// envelope's own code and can differ from the HTTP status (the handoff returns HTTP 201 with
// statusCode 200).
type Envelope struct {
	Status     json.RawMessage `json:"status,omitempty"`
	StatusCode int             `json:"statusCode,omitempty"`
	Message    string          `json:"message,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	Path       string          `json:"path,omitempty"`
	Timestamp  string          `json:"timestamp,omitempty"`
}

// Response is what every signed call returns.
type Response struct {
	// Status is the HTTP status code.
	Status int
	// OK is true for 2xx statuses.
	OK bool
	// Headers are the response headers.
	Headers http.Header
	// RawBody is the response body, always populated.
	RawBody []byte
}
