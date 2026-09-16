// Package codearts implements the Huawei Cloud CodeArts (CodeArts Work desktop
// client) authentication and request signing used by the CLIProxyAPI CodeArts
// provider.
//
// CodeArts is unlike the other browser-login providers in this repository: the
// desktop client never talks to the LLM with a bearer token. Instead it
//
//  1. runs an OAuth2 authorization-code + PKCE browser login with a DPoP proof
//     against the Huawei Cloud STS endpoint, and receives a *temporary* Huawei
//     Cloud AK/SK/security-token triple,
//  2. signs every subsequent business request with Huawei Cloud's
//     SDK-HMAC-SHA256 scheme using that AK/SK.
//
// This package mirrors both halves: the OAuth token exchange (oauth.go) and the
// request signer (sign.go).
package codearts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// StableHexID derives a deterministic lowercase hex id of n bytes from a seed.
// It is used for the synthetic chat-session correlation header so the same
// credential always reports the same session id.
func StableHexID(seed string, n int) string {
	if n <= 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(seed))
	if n > len(sum) {
		n = len(sum)
	}
	return hex.EncodeToString(sum[:n])
}

// Algorithm is the Huawei Cloud signing algorithm identifier.
const Algorithm = "SDK-HMAC-SHA256"

// SecurityTokenHeader carries the temporary security token of the credentials.
const SecurityTokenHeader = "X-Security-Token"

// SdkDateHeader is the signed request timestamp header.
const SdkDateHeader = "X-Sdk-Date"

// sdkDateFormat is the UTC timestamp format Huawei Cloud expects.
const sdkDateFormat = "20060102T150405Z"

// SignOptions describes one request to be signed.
type SignOptions struct {
	// Method is the HTTP method (case-insensitive).
	Method string
	// URL is the absolute request URL including any query string.
	URL string
	// Headers are extra headers to include in the signature. The signer always
	// adds host and X-Sdk-Date.
	Headers map[string]string
	// Body is the raw request body used for the payload hash.
	Body []byte
	// ContentSHA256, when set, is used verbatim as the payload hash instead of
	// hashing Body. It mirrors the X-Sdk-Content-Sha256 escape hatch.
	ContentSHA256 string
	// Now overrides the signing timestamp. Tests set this for determinism.
	Now func() time.Time
}

// Sign returns the headers to send, including Authorization, X-Sdk-Date and
// X-Security-Token. The returned map is a copy; opts.Headers is not mutated.
//
// The produced signature follows the Huawei Cloud SDK-HMAC-SHA256 canonical
// request layout:
//
//	METHOD\n
//	canonicalURI\n
//	canonicalQueryString\n
//	canonicalHeaders\n
//	signedHeaders\n
//	payloadHash
func Sign(opts SignOptions, accessKey, secretKey string) map[string]string {
	headers := make(map[string]string, len(opts.Headers)+4)
	for key, value := range opts.Headers {
		headers[key] = value
	}

	parsed, errParse := url.Parse(opts.URL)
	if errParse != nil {
		// An unparsable URL cannot be signed meaningfully; return the headers
		// unchanged so the caller surfaces the upstream error instead.
		return headers
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	sdkDate := now().UTC().Format(sdkDateFormat)

	headers["host"] = parsed.Host
	headers[SdkDateHeader] = sdkDate

	canonicalHeaders, signedHeaders := canonicalizeHeaders(headers)

	payloadHash := strings.TrimSpace(opts.ContentSHA256)
	if payloadHash == "" {
		sum := sha256.Sum256(opts.Body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	canonicalRequest := strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(opts.Method)),
		canonicalURI(parsed.Path),
		canonicalQueryString(parsed.Query()),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	requestSum := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		Algorithm,
		sdkDate,
		hex.EncodeToString(requestSum[:]),
	}, "\n")

	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))

	headers["Authorization"] = Algorithm + " Access=" + accessKey +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return headers
}

// canonicalURI percent-encodes every path segment and always appends a trailing
// slash, matching the Huawei Cloud signer.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	encoded := make([]string, 0, len(segments))
	for _, segment := range segments {
		encoded = append(encoded, escape(segment))
	}
	result := strings.Join(encoded, "/")
	if !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

// canonicalQueryString sorts the encoded key/value pairs.
func canonicalQueryString(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(values))
	for key, list := range values {
		for _, value := range list {
			pairs = append(pairs, escape(key)+"="+escape(value))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalizeHeaders lowercases and sorts the signed headers, returning the
// canonical block and the signed-headers list.
func canonicalizeHeaders(headers map[string]string) (string, string) {
	type entry struct {
		key   string
		value string
	}
	entries := make([]entry, 0, len(headers))
	for key, value := range headers {
		entries = append(entries, entry{key: strings.ToLower(strings.TrimSpace(key)), value: strings.TrimSpace(value)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	var block strings.Builder
	names := make([]string, 0, len(entries))
	for _, item := range entries {
		block.WriteString(item.key)
		block.WriteString(":")
		block.WriteString(item.value)
		block.WriteString("\n")
		names = append(names, item.key)
	}
	return block.String(), strings.Join(names, ";")
}

// escape percent-encodes a value following the Huawei Cloud signer rules:
// unreserved characters A-Z a-z 0-9 - _ . ~ are kept, everything else is
// percent-encoded with uppercase hex, and space becomes %20.
func escape(value string) string {
	const upperHex = "0123456789ABCDEF"
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9':
			builder.WriteByte(ch)
		case ch == '-' || ch == '_' || ch == '.' || ch == '~':
			builder.WriteByte(ch)
		default:
			builder.WriteByte('%')
			builder.WriteByte(upperHex[ch>>4])
			builder.WriteByte(upperHex[ch&0x0f])
		}
	}
	return builder.String()
}
