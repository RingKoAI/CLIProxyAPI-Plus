// Package qwenweb implements credential acquisition for Qwen's web session API.
// It is not an OAuth client; passwords are hashed for one sign-in and never retained.
package qwenweb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

const Provider = "qwen-web"
const BaseURL = "https://chat.qwen.ai"
const Version = "0.2.91"

type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string   { return e.Message }
func (e *Error) StatusCode() int { return e.Code }

// Headers follows the real web frontend, which authenticates with a Cookie and
// does not send Authorization on chat requests. The token is used only as a
// fallback when no Cookie is available.
func Headers(token, cookie string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json")
	h.Set("Origin", BaseURL)
	h.Set("Referer", BaseURL+"/")
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Version", Version)
	h.Set("source", "web")
	h.Set("X-Accel-Buffering", "no")
	h.Set("X-Request-Id", uuid.NewString())
	if cookie != "" {
		h.Set("Cookie", cookie)
	} else if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	return h
}

// Client only sends credentials to its fixed upstream. BaseURL is injectable for tests.
type Client struct {
	HTTP    *http.Client
	BaseURL string
}
type User struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Token  string `json:"token"`
	Cookie string `json:"-"`
}

type LoginInput struct {
	Method   string `json:"method"`
	Cookie   string `json:"cookie"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// SessionCookie rebuilds a Cookie header containing only Qwen's session token.
// Qwen's own frontend reads localStorage.token, then the qwen_token and token
// cookies. Analytics and tracking cookies are dropped because they are not
// required for authentication and would store unrelated third-party values.
func SessionCookie(cookies []*http.Cookie) string {
	for _, name := range []string{"token", "qwen_token"} {
		for _, cookie := range cookies {
			if cookie == nil || cookie.Name != name {
				continue
			}
			if !validToken(cookie.Value) {
				continue
			}
			return name + "=" + cookie.Value
		}
	}
	return ""
}

func validToken(s string) bool {
	return s != "" && len(s) <= 32768 && !strings.ContainsAny(s, "\r\n\t ")
}

// CookieToken recognizes only names used by Qwen's own frontend. It never treats
// an arbitrary cookie header (or analytics cookie) as an access token.
func CookieToken(raw string) (string, error) {
	if len(raw) > 65536 || strings.ContainsAny(raw, "\r\n") {
		return "", errors.New("invalid Cookie header")
	}
	r := &http.Request{Header: http.Header{"Cookie": {raw}}}
	cookies := r.Cookies()
	for _, name := range []string{"qwen_token", "token"} {
		var found string
		for _, cookie := range cookies {
			if cookie.Name != name {
				continue
			}
			value, err := url.PathUnescape(cookie.Value)
			if err != nil || !validToken(value) {
				return "", errors.New("invalid Qwen session cookie")
			}
			if found != "" && found != value {
				return "", errors.New("ambiguous Qwen session cookies")
			}
			found = value
		}
		if found != "" {
			return found, nil
		}
	}
	return "", nil
}

func (c *Client) Login(ctx context.Context, input LoginInput) (User, error) {
	token, cookie := "", ""
	switch input.Method {
	case "password":
		if strings.TrimSpace(input.Email) == "" || input.Password == "" || len(input.Password) > 1024 || len(input.Email) > 320 {
			return User{}, &Error{400, "email and password are required"}
		}
		sum := sha256.Sum256([]byte(input.Password))
		// The real frontend receives an HttpOnly token Cookie in the sign-in
		// response, and chat requests authenticate with that Cookie rather than
		// a Bearer token. Capture both.
		user, setCookie, err := c.userRequest(ctx, http.MethodPost, "/api/v2/auths/signin", "", "", map[string]string{"email": strings.TrimSpace(input.Email), "password": hex.EncodeToString(sum[:])})
		if err != nil {
			return User{}, err
		}
		token = user.Token
		cookie = setCookie
		if !validToken(token) {
			return User{}, &Error{401, "Qwen sign-in returned no usable token; complete verification on chat.qwen.ai and import a session"}
		}
	case "cookie":
		raw := strings.TrimSpace(input.Cookie)
		if raw == "" {
			return User{}, &Error{400, "Cookie header is required"}
		}
		var err error
		token, err = CookieToken(raw)
		if err != nil {
			return User{}, &Error{400, err.Error()}
		}
		// Store only the session cookie. A pasted header usually contains many
		// unrelated analytics and tracking cookies that must not be persisted.
		cookie = SessionCookie((&http.Request{Header: http.Header{"Cookie": {raw}}}).Cookies())
	case "token":
		token = strings.TrimSpace(input.Token)
		if !validToken(token) {
			return User{}, &Error{400, "a valid session token is required"}
		}
	default:
		return User{}, &Error{400, "method must be cookie, password or token"}
	}
	user, verifyCookie, err := c.userRequest(ctx, http.MethodGet, "/api/v1/auths/", token, cookie, nil)
	if err != nil {
		return User{}, err
	}
	if verifyCookie != "" {
		cookie = verifyCookie
	}
	if user.Token == "" {
		user.Token = token
	}
	if cookie != "" {
		user.Cookie = cookie
	}
	if !validToken(user.Token) {
		return User{}, &Error{401, "Cookie did not yield a usable Qwen session token; use qwen_token/token cookies or paste the localStorage token"}
	}
	return user, nil
}

func (c *Client) userRequest(ctx context.Context, method, path, token, cookie string, body any) (User, string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return User{}, "", &Error{400, "invalid sign-in request"}
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(raw)
	}
	base := c.BaseURL
	if base == "" {
		base = BaseURL
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return User{}, "", &Error{502, "could not create Qwen authentication request"}
	}
	req.Header = Headers(token, cookie)
	client := http.DefaultClient
	if c.HTTP != nil {
		client = c.HTTP
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := copyClient.Do(req)
	if err != nil {
		return User{}, "", &Error{502, "Qwen authentication connection failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	captured := SessionCookie(resp.Cookies())
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := 502
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			code = 401
		}
		if resp.StatusCode == 429 {
			code = 429
		}
		return User{}, "", &Error{code, fmt.Sprintf("Qwen authentication rejected (HTTP %d); verify credentials or complete login/verification on chat.qwen.ai", resp.StatusCode)}
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return User{}, "", &Error{502, "could not read Qwen authentication response"}
	}
	var envelope struct {
		Success *bool           `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return User{}, "", &Error{502, "invalid Qwen authentication response"}
	}
	if envelope.Success != nil {
		if !*envelope.Success {
			return User{}, "", &Error{401, "Qwen sign-in failed; check credentials, account activation or browser verification"}
		}
		raw = envelope.Data
	}
	var user User
	if json.Unmarshal(raw, &user) != nil || user.ID == "" || (user.Role != "user" && user.Role != "admin") {
		return User{}, "", &Error{401, "Qwen did not return an active account; complete account verification on chat.qwen.ai"}
	}
	return user, captured, nil
}
