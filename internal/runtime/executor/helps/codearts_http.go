package helps

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	codeartsauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codearts"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// CodeArtsSessionHeader carries the synthetic chat-session id upstream.
const CodeArtsSessionHeader = "user-session-id"

// codeArtsSigningRoundTripper signs every outbound CodeArts request with Huawei
// Cloud SDK-HMAC-SHA256.
//
// Signing happens at the transport so the signature always covers the exact
// bytes that are written to the wire — the OpenAI-compatible executor builds and
// rewrites the body before dispatch, so signing earlier would sign stale bytes.
type codeArtsSigningRoundTripper struct {
	base         http.RoundTripper
	accessKey    string
	secretKey    string
	securityToke string
	sessionID    string
}

// RoundTrip signs the request and forwards it.
func (t *codeArtsSigningRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, nil
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	var body []byte
	if req.Body != nil {
		read, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			return nil, errRead
		}
		body = read
		if errClose := req.Body.Close(); errClose != nil {
			return nil, errClose
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	}

	// The Huawei Cloud signature replaces the bearer credential the
	// OpenAI-compatible executor sets.
	req.Header.Del("Authorization")
	if t.securityToke != "" {
		req.Header.Set(codeartsauth.SecurityTokenHeader, t.securityToke)
		req.Header.Set("x-auth-token", t.securityToke)
	}
	if t.sessionID != "" {
		req.Header.Set(CodeArtsSessionHeader, t.sessionID)
	}
	req.Header.Set("Accept-Encoding", "identity")

	// The desktop client signs exactly these three headers.
	signHeaders := map[string]string{}
	if t.securityToke != "" {
		signHeaders[codeartsauth.SecurityTokenHeader] = t.securityToke
	}
	signed := codeartsauth.Sign(codeartsauth.SignOptions{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: signHeaders,
		Body:    body,
	}, t.accessKey, t.secretKey)
	for key, value := range signed {
		req.Header.Set(key, value)
	}

	return base.RoundTrip(req)
}

// NewCodeArtsHTTPClient creates the HTTP client used for CodeArts requests.
//
// CodeArts authenticates with a Huawei Cloud temporary AK/SK triple rather than
// a bearer token, so the client installs a signing round tripper that covers the
// final request bytes.
func NewCodeArtsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	base := NewProxyAwareHTTPClient(ctx, cfg, auth, timeout)
	if base == nil {
		base = &http.Client{}
	}
	if auth == nil {
		return base
	}

	accessKey, secretKey, securityToken := CodeArtsCredentialTriple(auth)
	if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
		return base
	}

	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	base.Transport = &codeArtsSigningRoundTripper{
		base:         transport,
		accessKey:    accessKey,
		secretKey:    secretKey,
		securityToke: securityToken,
		sessionID:    CodeArtsSessionIDFromAuth(auth),
	}
	return base
}

// CodeArtsCredentialTriple reads the signed-request credential triple from auth
// attributes, falling back to metadata.
func CodeArtsCredentialTriple(auth *cliproxyauth.Auth) (accessKey, secretKey, securityToken string) {
	if auth == nil {
		return "", "", ""
	}
	read := func(attrKey, metaKey string) string {
		if auth.Attributes != nil {
			if value := strings.TrimSpace(auth.Attributes[attrKey]); value != "" {
				return value
			}
		}
		if auth.Metadata != nil {
			if value, ok := auth.Metadata[metaKey].(string); ok {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	return read("api_key", "access_key"),
		read("secret_key", "secret_key"),
		read("security_token", "security_token")
}

// CodeArtsSessionIDFromAuth returns a stable chat-session id for correlation
// headers, deriving one from the credential when none is recorded.
func CodeArtsSessionIDFromAuth(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if value, ok := auth.Metadata["session_id"].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	accessKey, _, _ := CodeArtsCredentialTriple(auth)
	return CodeArtsStableSessionID(auth.ID + "|" + accessKey)
}

// CodeArtsStableSessionID derives a deterministic session id from a seed.
func CodeArtsStableSessionID(seed string) string {
	if strings.TrimSpace(seed) == "" {
		return ""
	}
	return codeartsauth.StableHexID(seed, 16)
}
