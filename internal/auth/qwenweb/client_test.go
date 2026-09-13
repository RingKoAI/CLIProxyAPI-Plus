package qwenweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCookieToken(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		bad       bool
	}{
		{"analytics=ignored; qwen_token=session%2Bvalue", "session+value", false},
		{"token=legacy; other=x", "legacy", false},
		{"analytics=only", "", false},
		{"qwen_token=a; qwen_token=b", "", true},
		{"token=bad%0Atoken", "", true},
		{"token=x\r\nHost: evil", "", true},
	} {
		got, err := CookieToken(tc.raw)
		if (err != nil) != tc.bad || got != tc.want {
			t.Errorf("CookieToken(%q)=(%q,%v)", tc.raw, got, err)
		}
	}
}
func TestPasswordLoginUsesHashAndVerifiesSession(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++

		switch r.URL.Path {
		case "/api/v2/auths/signin":
			if r.Method != "POST" {
				t.Error("wrong method")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte("not-a-real-password"))
			if body["password"] != hex.EncodeToString(digest[:]) || body["email"] != "test@example.com" {
				t.Error("wrong sign-in payload")
			}
			fmt.Fprint(w, `{"success":true,"data":{"id":"account-1","email":"test@example.com","role":"user","token":"test-session"}}`)
		case "/api/v1/auths/":
			if r.Header.Get("Authorization") != "Bearer test-session" {
				t.Error("missing verified bearer")
			}
			fmt.Fprint(w, `{"id":"account-1","email":"test@example.com","role":"user"}`)
		default:
			t.Error("unexpected endpoint")
		}
	}))
	defer server.Close()
	user, err := (&Client{HTTP: server.Client(), BaseURL: server.URL}).Login(context.Background(), LoginInput{Method: "password", Email: "test@example.com", Password: "not-a-real-password"})
	if err != nil || user.Token != "test-session" || calls != 2 {
		t.Fatalf("login failed: user=%+v err=%v calls=%d", user, err, calls)
	}
}
func TestCookieLoginSessionExchange(t *testing.T) {
	for _, tokenCookie := range []bool{false, true} {
		t.Run(fmt.Sprint(tokenCookie), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Only a recognizable session cookie is forwarded. An opaque cookie
				// yields no credential, so the server rejects the request.
				if tokenCookie && r.Header.Get("Cookie") == "" {
					t.Error("session cookie not sent")
				}
				if !tokenCookie && r.Header.Get("Cookie") != "" {
					t.Error("opaque cookie must not be used as a credential")
				}
				// The real web frontend authenticates with the Cookie and sends no
				// Authorization header, for both recognized and opaque cookies.
				if r.Header.Get("Authorization") != "" {
					t.Error("Authorization must not be sent when a cookie is present")
				}
				if r.Header.Get("source") != "web" {
					t.Error("expected the web source header")
				}
				fmt.Fprint(w, `{"id":"account","role":"user","token":"session"}`)
			}))
			defer server.Close()
			cookie := "opaque-session=value"
			if tokenCookie {
				cookie = "qwen_token=session"
			}
			user, err := (&Client{HTTP: server.Client(), BaseURL: server.URL}).Login(context.Background(), LoginInput{Method: "cookie", Cookie: cookie})
			if err != nil || user.Token != "session" {
				t.Fatalf("user=%+v err=%v", user, err)
			}
		})
	}
}
func TestLoginRejectsInvalidResponsesAndRedactsErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"unauthorized", `{"detail":"secret-value"}`, 401},
		{"html", "<html>secret-value</html>", 200},
		{"false-success", `{"success":false,"data":{"details":"secret-value"}}`, 200},
		{"pending", `{"success":true,"data":{"id":"id","role":"pending","token":"secret-value"}}`, 200},
		{"missing-id", `{"role":"user","token":"secret-value"}`, 200},
		{"no-session-token", `{"id":"id","role":"user"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			_, err := (&Client{HTTP: server.Client(), BaseURL: server.URL}).Login(context.Background(), LoginInput{Method: "cookie", Cookie: "analytics=secret-value"})
			if err == nil {
				t.Fatal("accepted invalid response")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatal("leaked upstream credential")
			}
		})
	}
}
func TestLoginDoesNotFollowRedirect(t *testing.T) {
	hit := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer source.Close()
	_, err := (&Client{HTTP: source.Client(), BaseURL: source.URL}).Login(context.Background(), LoginInput{Method: "token", Token: "test-session"})
	if err == nil || hit {
		t.Fatalf("redirect followed: %v %v", err, hit)
	}
}

func TestHeadersPreferWebSourceAndCookie(t *testing.T) {
	h := Headers("tok", "token=session")
	if h.Get("source") != "web" {
		t.Errorf("source = %q, want web (the real frontend sends web)", h.Get("source"))
	}
	if h.Get("Cookie") != "token=session" || h.Get("Authorization") != "" {
		t.Errorf("cookie mode must not send Authorization: %v", h)
	}
	if h.Get("X-Accel-Buffering") != "no" || h.Get("Version") == "" {
		t.Errorf("missing web headers: %v", h)
	}
	h = Headers("tok", "")
	if h.Get("Authorization") != "Bearer tok" {
		t.Errorf("token fallback missing: %v", h)
	}
}

func TestSessionCookieKeepsOnlyToken(t *testing.T) {
	got := SessionCookie([]*http.Cookie{
		{Name: "token", Value: "session"},
		{Name: "x-ap", Value: "pop"},
		{Name: "tfstk", Value: "tracking"},
	})
	if got != "token=session" {
		t.Fatalf("SessionCookie() = %q", got)
	}
	if SessionCookie([]*http.Cookie{{Name: "analytics", Value: "x"}}) != "" {
		t.Fatal("unrelated cookie kept")
	}
}

func TestPasswordLoginCapturesCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auths/signin" {
			http.SetCookie(w, &http.Cookie{Name: "token", Value: "cookie-session", HttpOnly: true, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "x-ap", Value: "pop"})
			fmt.Fprint(w, `{"success":true,"data":{"id":"a","role":"user","token":"json-session"}}`)
			return
		}
		fmt.Fprint(w, `{"id":"a","role":"user","token":"json-session"}`)
	}))
	defer server.Close()
	user, err := (&Client{HTTP: server.Client(), BaseURL: server.URL}).Login(context.Background(), LoginInput{Method: "password", Email: "u@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	// Both are kept: the web frontend uses the Cookie, the token is the fallback.
	if user.Cookie != "token=cookie-session" {
		t.Fatalf("cookie = %q", user.Cookie)
	}
	if user.Token != "json-session" {
		t.Fatalf("token = %q", user.Token)
	}
}
