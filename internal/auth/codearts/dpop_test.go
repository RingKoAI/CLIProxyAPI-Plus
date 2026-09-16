package codearts

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// decodeJWTHeader decodes the protected header of a compact JWS.
func decodeJWTHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d (%s)", len(parts), token)
	}
	raw, errDecode := base64.RawURLEncoding.DecodeString(parts[0])
	if errDecode != nil {
		t.Fatalf("decode header: %v", errDecode)
	}
	var header map[string]any
	if errUnmarshal := json.Unmarshal(raw, &header); errUnmarshal != nil {
		t.Fatalf("unmarshal header: %v", errUnmarshal)
	}
	return header
}

// TestSignDpopProofShape pins the DPoP proof shape Huawei Cloud STS accepts.
//
// Verified against the live sts.cn-north-4.myhuaweicloud.com endpoint: a proof
// with this exact shape advances the response from "Invalid header parameter:
// DPoP, required" (APIGW.0106) to code validation (STS5.1805).
func TestSignDpopProofShape(t *testing.T) {
	keyPair, errGenerate := GenerateDpopKeyPair()
	if errGenerate != nil {
		t.Fatalf("generate key pair: %v", errGenerate)
	}
	endpoint := IAMSTSHost + TokenPath
	proof, errProof := SignDpopProof(keyPair, http.MethodPost, endpoint)
	if errProof != nil {
		t.Fatalf("sign proof: %v", errProof)
	}

	header := decodeJWTHeader(t, proof)
	if header["alg"] != "ES256" {
		t.Fatalf("alg = %v, want ES256", header["alg"])
	}
	if header["typ"] != "dpop+jwt" {
		t.Fatalf("typ = %v, want dpop+jwt", header["typ"])
	}

	// The JWK must be a structured object with the public coordinates only.
	jwkRaw, errMarshal := json.Marshal(header["jwk"])
	if errMarshal != nil {
		t.Fatalf("marshal jwk: %v", errMarshal)
	}
	var publicKey jwk
	if errUnmarshal := json.Unmarshal(jwkRaw, &publicKey); errUnmarshal != nil {
		t.Fatalf("unmarshal jwk: %v", errUnmarshal)
	}
	if publicKey.Kty != "EC" || publicKey.Crv != "P-256" {
		t.Fatalf("unexpected jwk: %+v", publicKey)
	}
	if publicKey.X == "" || publicKey.Y == "" {
		t.Fatalf("jwk is missing public coordinates: %+v", publicKey)
	}
	if publicKey.D != "" {
		t.Fatalf("jwk must not leak the private key: %s", jwkRaw)
	}

	// The payload must bind method and URL.
	payloadRaw, errPayload := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[1])
	if errPayload != nil {
		t.Fatalf("decode payload: %v", errPayload)
	}
	var payload struct {
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
	}
	if errUnmarshal := json.Unmarshal(payloadRaw, &payload); errUnmarshal != nil {
		t.Fatalf("unmarshal payload: %v", errUnmarshal)
	}
	if payload.HTM != http.MethodPost {
		t.Fatalf("htm = %q, want POST", payload.HTM)
	}
	if payload.HTU != endpoint {
		t.Fatalf("htu = %q, want %q", payload.HTU, endpoint)
	}
	if payload.JTI == "" || payload.IAT == 0 {
		t.Fatalf("payload is missing jti/iat: %+v", payload)
	}
}

// TestSignDpopProofVerifiesWithPublicKey checks the ES256 signature itself.
func TestSignDpopProofVerifiesWithPublicKey(t *testing.T) {
	keyPair, errGenerate := GenerateDpopKeyPair()
	if errGenerate != nil {
		t.Fatalf("generate key pair: %v", errGenerate)
	}
	proof, errProof := SignDpopProof(keyPair, http.MethodPost, "https://example.com/v1/oauth2/tokens")
	if errProof != nil {
		t.Fatalf("sign proof: %v", errProof)
	}

	parts := strings.Split(proof, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, errDecode := base64.RawURLEncoding.DecodeString(parts[2])
	if errDecode != nil {
		t.Fatalf("decode signature: %v", errDecode)
	}
	if len(signature) != 64 {
		t.Fatalf("P-256 signature must be 64 bytes, got %d", len(signature))
	}

	privateKey, errParse := parsePrivateKey(keyPair.PrivateKey)
	if errParse != nil {
		t.Fatalf("parse private key: %v", errParse)
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&privateKey.PublicKey, digest[:], r, s) {
		t.Fatal("DPoP signature did not verify against the derived public key")
	}
}

// TestDpopKeyPairRoundTrip pins that the persisted JWK survives a parse.
func TestDpopKeyPairRoundTrip(t *testing.T) {
	keyPair, errGenerate := GenerateDpopKeyPair()
	if errGenerate != nil {
		t.Fatalf("generate key pair: %v", errGenerate)
	}
	parsed, errParse := parsePrivateKey(keyPair.PrivateKey)
	if errParse != nil {
		t.Fatalf("parse private key: %v", errParse)
	}
	if parsed.Curve.Params().Name != "P-256" {
		t.Fatalf("curve = %s, want P-256", parsed.Curve.Params().Name)
	}
	// A differently-seeded proof must differ, proving the key is used.
	first, _ := SignDpopProof(keyPair, http.MethodPost, "https://example.com/a")
	second, _ := SignDpopProof(keyPair, http.MethodPost, "https://example.com/a")
	if first == second {
		t.Fatal("proofs must differ because jti is random")
	}
}

// TestGeneratePKCEPair pins the PKCE verifier/challenge derivation.
func TestGeneratePKCEPair(t *testing.T) {
	verifier, challenge, errGenerate := GeneratePKCEPair()
	if errGenerate != nil {
		t.Fatalf("generate PKCE: %v", errGenerate)
	}
	// The desktop client uses hex(randomBytes(64)) -> 128 hex characters.
	if len(verifier) != 128 {
		t.Fatalf("verifier length = %d, want 128", len(verifier))
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("challenge = %q, want %q", challenge, want)
	}
}
