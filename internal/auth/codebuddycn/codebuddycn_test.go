package codebuddycn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientDeviceFlow(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/state":
			if r.Method != http.MethodPost || r.URL.Query().Get("platform") != "CLI" {
				t.Fatalf("state request = %s %s", r.Method, r.URL.String())
			}
			if got := r.Header.Get("X-Domain"); got != "copilot.tencent.com" {
				t.Fatalf("X-Domain = %q", got)
			}
			_, _ = fmt.Fprint(w, `{"code":0,"data":{"state":"state-1","authUrl":"https://example.test/authorize"}}`)
		case "/token":
			if r.Method != http.MethodGet || r.URL.Query().Get("state") != "state-1" {
				t.Fatalf("token request = %s %s", r.Method, r.URL.String())
			}
			if polls.Add(1) == 1 {
				_, _ = fmt.Fprint(w, `{"code":11217,"msg":"pending"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"code":0,"data":{"accessToken":"access-1","refreshToken":"refresh-1","tokenType":"Bearer","expiresIn":3600}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newClient(server.Client(), server.URL+"/state", server.URL+"/token", server.URL+"/refresh", "copilot.tencent.com")
	device, err := client.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow() error = %v", err)
	}
	device.Interval = time.Millisecond
	token, err := client.WaitForAuthorization(context.Background(), device)
	if err != nil {
		t.Fatalf("WaitForAuthorization() error = %v", err)
	}
	if token.AccessToken != "access-1" || token.RefreshToken != "refresh-1" || token.ExpiresAt.IsZero() {
		t.Fatalf("token = %#v", token)
	}
}

func TestClientRefreshUsesHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if got := r.Header.Get("X-Refresh-Token"); got != "refresh-old" {
			t.Fatalf("X-Refresh-Token = %q", got)
		}
		if got := r.Header.Get("X-Auth-Refresh-Source"); got != "plugin" {
			t.Fatalf("X-Auth-Refresh-Source = %q", got)
		}
		_, _ = fmt.Fprint(w, `{"code":0,"data":{"accessToken":"access-new","refreshToken":"refresh-new","expiresIn":7200}}`)
	}))
	defer server.Close()

	client := newClient(server.Client(), server.URL, server.URL, server.URL, "copilot.tencent.com")
	token, err := client.Refresh(context.Background(), " refresh-old ")
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if token.AccessToken != "access-new" || token.RefreshToken != "refresh-new" {
		t.Fatalf("token = %#v", token)
	}
}

func TestParseTokenResponseRejectsMissingAccessToken(t *testing.T) {
	_, err := parseTokenResponse([]byte(`{"code":0,"data":{"refreshToken":"refresh-only"}}`))
	if err == nil || !strings.Contains(err.Error(), "missing access token") {
		t.Fatalf("error = %v", err)
	}
}

func TestAIClientUsesInternationalHostAndDomain(t *testing.T) {
	var gotDomain, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDomain = r.Header.Get("X-Domain")
		gotPath = r.URL.Path
		_, _ = fmt.Fprint(w, `{"code":0,"data":{"state":"s","authUrl":"https://example.test/authorize"}}`)
	}))
	defer server.Close()

	client := newClient(server.Client(), server.URL+"/state", server.URL+"/token", server.URL+"/refresh", AIHost)
	if _, err := client.StartDeviceFlow(context.Background()); err != nil {
		t.Fatalf("StartDeviceFlow() error = %v", err)
	}
	if gotDomain != AIHost {
		t.Fatalf("X-Domain = %q, want %q", gotDomain, AIHost)
	}
	if gotPath != "/state" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestAIClientDefaultsDomainWhenEmpty(t *testing.T) {
	client := newClient(nil, "https://example.test/state", "https://example.test/token", "https://example.test/refresh", "")
	if client.domain != "copilot.tencent.com" {
		t.Fatalf("domain = %q, want default", client.domain)
	}
}
