package partnersigned

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client sends signed requests. It works for both HMAC and Ed25519 and for BOTH directions of the
// protocol:
//
//   - Calling INTO BanglaReels (any endpoint under PartnerSignatureGuard): set PartnerID so that
//     X-Partner-Id is sent.
//   - Simulating what BanglaReels sends OUT to a partner's own /deduct endpoint: leave PartnerID
//     empty, since that direction never sends it.
//
// The zero value is ready to use.
type Client struct {
	// HTTPClient is used to send requests. Nil means http.DefaultClient.
	HTTPClient *http.Client
}

// NewClient returns a Client that sends requests with httpClient (nil means http.DefaultClient).
func NewClient(httpClient *http.Client) *Client {
	return &Client{HTTPClient: httpClient}
}

var defaultClient = &Client{}

// SignedRequest signs and sends a request with the default client.
func SignedRequest(ctx context.Context, opts SignedRequestOptions) (*Response, error) {
	return defaultClient.SignedRequest(ctx, opts)
}

// Handoff calls POST {baseUrl}{apiPrefix}/partner/auth/handoff with the default client.
func Handoff(ctx context.Context, opts HandoffOptions) (*Response, error) {
	return defaultClient.Handoff(ctx, opts)
}

// SignedRequest signs and sends a request to any partner-signed endpoint.
func (c *Client) SignedRequest(ctx context.Context, opts SignedRequestOptions) (*Response, error) {
	switch {
	case opts.BaseURL == "":
		return nil, errors.New(`partnersigned: "BaseURL" is required`)
	case opts.Path == "":
		return nil, errors.New(`partnersigned: "Path" is required`)
	case opts.Scheme == "":
		return nil, errors.New(`partnersigned: "Scheme" is required ("hmac" | "ed25519")`)
	case opts.Secret == "":
		return nil, errors.New(`partnersigned: "Secret" is required`)
	}

	requestID := opts.RequestID
	if requestID == "" {
		var err error
		if requestID, err = newUUID(); err != nil {
			return nil, err
		}
	}
	method := opts.Method
	if method == "" {
		method = http.MethodPost
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	// Signed and sent as the EXACT same bytes: re-serializing after signing (e.g. a different key
	// order) would produce a body whose hash no longer matches the signature.
	var rawBody []byte
	if opts.Body != nil {
		var err error
		if rawBody, err = MarshalBody(opts.Body); err != nil {
			return nil, err
		}
	}

	signature, err := Sign(opts.Scheme, BuildSigningString(timestamp, requestID, rawBody), opts.Secret)
	if err != nil {
		return nil, err
	}

	path := opts.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := strings.TrimRight(opts.BaseURL, "/") + path

	var body io.Reader
	if len(rawBody) > 0 {
		body = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderRequestID, requestID)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderSignature, signature)
	if opts.PartnerID != "" {
		req.Header.Set(HeaderPartnerID, opts.PartnerID)
	}
	for name, value := range opts.ExtraHeaders {
		req.Header.Set(name, value)
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{
		Status:  resp.StatusCode,
		OK:      resp.StatusCode >= 200 && resp.StatusCode < 300,
		Headers: resp.Header,
		RawBody: respBody,
	}, nil
}

// Handoff is the actual flow: sign and call POST {baseUrl}{apiPrefix}/partner/auth/handoff. On
// success, read the result with resp.DecodeData(&HandoffResult{}) because the API wraps it in an
// envelope.
func (c *Client) Handoff(ctx context.Context, opts HandoffOptions) (*Response, error) {
	switch {
	case opts.PartnerID == "":
		return nil, errors.New(`partnersigned: "PartnerID" (X-Partner-Id) is required for handoff`)
	case opts.PartnerUserID == "":
		return nil, errors.New(`partnersigned: "PartnerUserID" is required`)
	case opts.PhoneNumber == "":
		return nil, errors.New(`partnersigned: "PhoneNumber" is required`)
	}

	prefix := opts.APIPrefix
	if prefix == "" {
		prefix = DefaultAPIPrefix
	}
	return c.SignedRequest(ctx, SignedRequestOptions{
		BaseURL:   opts.BaseURL,
		Path:      prefix + "/partner/auth/handoff",
		Method:    http.MethodPost,
		Scheme:    opts.Scheme,
		Secret:    opts.Secret,
		PartnerID: opts.PartnerID,
		RequestID: opts.RequestID,
		Body: HandoffRequest{
			PartnerUserID: opts.PartnerUserID,
			PhoneNumber:   opts.PhoneNumber,
			Name:          opts.Name,
			Email:         opts.Email,
			ReturnPath:    opts.ReturnPath,
		},
	})
}

// MarshalBody serializes v the way JSON.stringify does, so the Go client sends the same bytes as
// the Node client: no HTML escaping of <, > and &, raw UTF-8 for non-ASCII, and no trailing
// newline. Use omitempty tags for fields that should be left out when empty.
func MarshalBody(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("partnersigned: encoding body: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// IsJSON reports whether the response declares a JSON content type.
func (r *Response) IsJSON() bool {
	mediaType, _, err := mime.ParseMediaType(r.Headers.Get("Content-Type"))
	return err == nil && strings.Contains(mediaType, "json")
}

// Decode unmarshals the whole response body into v.
func (r *Response) Decode(v any) error {
	return json.Unmarshal(r.RawBody, v)
}

// Envelope unmarshals BanglaReels' response envelope {status, statusCode, message, data}.
func (r *Response) Envelope() (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(r.RawBody, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// DecodeData unmarshals the payload inside BanglaReels' response envelope into v, e.g.
// resp.DecodeData(&result) with a HandoffResult. If the body is a JSON object without a "data"
// field, the whole body is decoded instead.
func (r *Response) DecodeData(v any) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(r.RawBody, &root); err == nil {
		if data, ok := root["data"]; ok {
			return json.Unmarshal(data, v)
		}
	}
	return json.Unmarshal(r.RawBody, v)
}

// DataAs is a generic form of Response.DecodeData.
func DataAs[T any](r *Response) (T, error) {
	var v T
	err := r.DecodeData(&v)
	return v, err
}

// newUUID returns a random (version 4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
