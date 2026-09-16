package codearts

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSignGoldenVector reproduces a signature captured from the real CodeArts
// agent-kernel (resources/bin/agent-kernel.exe) talking to a local mock of the
// InferHub gateway. It pins the exact canonical-request layout Huawei Cloud STS
// and the business gateway accept, so a refactor cannot silently change it.
//
// The capture was taken with AK=AK_TEST_ACCESS, SK=SK_TEST_SECRET,
// X-Security-Token=SECURITY_TOKEN_TEST and the recorded request body.
func TestSignGoldenVector(t *testing.T) {
	body, errRead := os.ReadFile(filepath.Join("testdata", "golden_body.bin"))
	if errRead != nil {
		t.Fatalf("read golden body: %v", errRead)
	}

	const (
		accessKey     = "AK_TEST_ACCESS"
		secretKey     = "SK_TEST_SECRET"
		securityToken = "SECURITY_TOKEN_TEST"
		wantSignature = "41cc3658aaa4dd2829d81f7b12afe3ad480cdae83bfbec56a397b9f77e7c4ab8"
		wantDate      = "20260916T071317Z"
	)

	headers := Sign(SignOptions{
		Method: "POST",
		URL:    "http://127.0.0.1/api/v2/chat/completions",
		Headers: map[string]string{
			SecurityTokenHeader: securityToken,
		},
		Body: body,
		Now: func() time.Time {
			parsed, errParse := time.Parse("20060102T150405Z", wantDate)
			if errParse != nil {
				t.Fatalf("parse fixed date: %v", errParse)
			}
			return parsed
		},
	}, accessKey, secretKey)

	gotDate := headers[SdkDateHeader]
	if gotDate != wantDate {
		t.Fatalf("X-Sdk-Date = %q, want %q", gotDate, wantDate)
	}

	authorization := headers["Authorization"]
	if !strings.Contains(authorization, "Signature="+wantSignature) {
		t.Fatalf("Authorization signature mismatch:\n got: %s\nwant signature: %s", authorization, wantSignature)
	}
	if !strings.Contains(authorization, "Access="+accessKey) {
		t.Fatalf("Authorization access key missing: %s", authorization)
	}
	// The desktop client signs exactly these three headers.
	if !strings.Contains(authorization, "SignedHeaders=host;x-sdk-date;x-security-token") {
		t.Fatalf("SignedHeaders mismatch: %s", authorization)
	}
}

// TestSignCanonicalURIAppendsTrailingSlash pins the trailing-slash rule.
func TestSignCanonicalURIAppendsTrailingSlash(t *testing.T) {
	cases := map[string]string{
		"":                         "/",
		"/v1/oauth2/tokens":        "/v1/oauth2/tokens/",
		"/api/v2/chat/completions": "/api/v2/chat/completions/",
		"/v1/model/builtin/":       "/v1/model/builtin/",
	}
	for input, want := range cases {
		if got := canonicalURI(input); got != want {
			t.Errorf("canonicalURI(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestSignCanonicalQuerySortsAndEncodes pins the query canonicalization.
func TestSignCanonicalQuerySortsAndEncodes(t *testing.T) {
	values, errParse := url.ParseQuery("b=2&a=1&a=0&c=x y")
	if errParse != nil {
		t.Fatalf("parse query: %v", errParse)
	}
	got := canonicalQueryString(values)
	want := "a=0&a=1&b=2&c=x%20y"
	if got != want {
		t.Fatalf("canonicalQueryString = %q, want %q", got, want)
	}
}

// TestSignHeadersAreCaseInsensitive pins that header names are lowercased and
// sorted in the signed-headers list.
func TestSignHeadersAreCaseInsensitive(t *testing.T) {
	headers := Sign(SignOptions{
		Method: "GET",
		URL:    "https://sts.cn-north-4.myhuaweicloud.com/v5/caller-identity",
		Headers: map[string]string{
			"X-Security-Token": "token-value",
			"Content-Type":     "application/json",
		},
		Now: func() time.Time { return time.Unix(0, 0).UTC() },
	}, "AK", "SK")

	authorization := headers["Authorization"]
	// host, x-sdk-date, x-security-token and content-type are all present and sorted.
	if !strings.Contains(authorization, "SignedHeaders=content-type;host;x-sdk-date;x-security-token") {
		t.Fatalf("unexpected SignedHeaders: %s", authorization)
	}
}

// TestSignPayloadHashUsesRawBody pins that the payload hash is the SHA-256 of
// the exact body bytes, so streamed/whitespace-preserved bodies stay valid.
func TestSignPayloadHashUsesRawBody(t *testing.T) {
	body := []byte(`{"model":"GLM-5.2", "stream": true}`)
	headers := Sign(SignOptions{
		Method: "POST",
		URL:    "https://example.com/api/v2/chat/completions",
		Body:   body,
		Now:    func() time.Time { return time.Unix(0, 0).UTC() },
	}, "AK", "SK")
	if headers["Authorization"] == "" {
		t.Fatal("signature was not produced")
	}

	// The important property is that the signer hashes the body verbatim.
	// Re-signing with a whitespace change must produce a different signature.
	altered := Sign(SignOptions{
		Method: "POST",
		URL:    "https://example.com/api/v2/chat/completions",
		Body:   []byte(`{"model":"GLM-5.2","stream":true}`),
		Now:    func() time.Time { return time.Unix(0, 0).UTC() },
	}, "AK", "SK")
	if headers["Authorization"] == altered["Authorization"] {
		t.Fatal("signature must depend on the exact body bytes")
	}
}
