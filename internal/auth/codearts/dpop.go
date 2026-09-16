package codearts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// dpopTyp is the JWT "typ" header value for a DPoP proof.
const dpopTyp = "dpop+jwt"

// DpopKeyPair holds a P-256 key pair serialized as JWK JSON.
//
// The private key must be persisted with the credentials: Huawei Cloud STS
// requires the refresh request to be signed by the same key that performed the
// original authorization-code exchange, so a login without the stored key can
// never be refreshed.
type DpopKeyPair struct {
	// PrivateKey is the private JWK as a JSON object string.
	PrivateKey string
	// PublicKey is the public JWK as a JSON object string.
	PublicKey string
}

// jwk is the JSON Web Key shape used for P-256 keys.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

// dpopHeader is the DPoP JWT protected header. JWK is embedded as a raw object
// so it is serialized exactly like a JWK rather than as a JSON string.
type dpopHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ"`
	JWK json.RawMessage `json:"jwk"`
}

// GenerateDpopKeyPair creates a fresh ES256 (P-256) key pair.
func GenerateDpopKeyPair() (*DpopKeyPair, error) {
	privateKey, errGenerate := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errGenerate != nil {
		return nil, fmt.Errorf("codearts: generate DPoP key pair: %w", errGenerate)
	}
	return marshalDpopKeyPair(privateKey)
}

// marshalDpopKeyPair renders a key pair as JWK JSON strings.
func marshalDpopKeyPair(privateKey *ecdsa.PrivateKey) (*DpopKeyPair, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("codearts: nil DPoP key")
	}
	size := (privateKey.Curve.Params().BitSize + 7) / 8

	publicJWK := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(padBytes(privateKey.X.Bytes(), size)),
		Y:   base64.RawURLEncoding.EncodeToString(padBytes(privateKey.Y.Bytes(), size)),
	}
	privateJWK := publicJWK
	privateJWK.D = base64.RawURLEncoding.EncodeToString(padBytes(privateKey.D.Bytes(), size))

	publicJSON, errPublic := json.Marshal(publicJWK)
	if errPublic != nil {
		return nil, fmt.Errorf("codearts: encode DPoP public key: %w", errPublic)
	}
	privateJSON, errPrivate := json.Marshal(privateJWK)
	if errPrivate != nil {
		return nil, fmt.Errorf("codearts: encode DPoP private key: %w", errPrivate)
	}
	return &DpopKeyPair{PrivateKey: string(privateJSON), PublicKey: string(publicJSON)}, nil
}

// parsePrivateKey decodes the stored private JWK.
func parsePrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("codearts: DPoP private key is empty")
	}
	var parsed jwk
	if errUnmarshal := json.Unmarshal([]byte(trimmed), &parsed); errUnmarshal != nil {
		return nil, fmt.Errorf("codearts: decode DPoP private key: %w", errUnmarshal)
	}
	xBytes, errX := base64.RawURLEncoding.DecodeString(parsed.X)
	if errX != nil {
		return nil, fmt.Errorf("codearts: decode DPoP x: %w", errX)
	}
	yBytes, errY := base64.RawURLEncoding.DecodeString(parsed.Y)
	if errY != nil {
		return nil, fmt.Errorf("codearts: decode DPoP y: %w", errY)
	}
	dBytes, errD := base64.RawURLEncoding.DecodeString(parsed.D)
	if errD != nil {
		return nil, fmt.Errorf("codearts: decode DPoP d: %w", errD)
	}
	curve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		},
		D: new(big.Int).SetBytes(dBytes),
	}
	return privateKey, nil
}

// publicJWKRaw returns the public JWK JSON exactly as it must appear in the DPoP
// protected header.
func publicJWKRaw(privateKey *ecdsa.PrivateKey) (json.RawMessage, error) {
	size := (privateKey.Curve.Params().BitSize + 7) / 8
	encoded, errMarshal := json.Marshal(jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(padBytes(privateKey.X.Bytes(), size)),
		Y:   base64.RawURLEncoding.EncodeToString(padBytes(privateKey.Y.Bytes(), size)),
	})
	if errMarshal != nil {
		return nil, fmt.Errorf("codearts: encode DPoP public JWK: %w", errMarshal)
	}
	return encoded, nil
}

// SignDpopProof builds the "DPoP" JWT for one request.
//
// The proof binds the HTTP method and URL (htm/htu) and carries the public JWK
// in its protected header, which is what lets STS verify the proof belongs to
// the key that later signs refresh requests.
func SignDpopProof(keyPair *DpopKeyPair, method, requestURL string) (string, error) {
	if keyPair == nil {
		return "", fmt.Errorf("codearts: DPoP key pair is required")
	}
	privateKey, errKey := parsePrivateKey(keyPair.PrivateKey)
	if errKey != nil {
		return "", errKey
	}
	publicJWK, errJWK := publicJWKRaw(privateKey)
	if errJWK != nil {
		return "", errJWK
	}

	header := dpopHeader{Alg: "ES256", Typ: dpopTyp, JWK: publicJWK}
	headerJSON, errHeader := json.Marshal(header)
	if errHeader != nil {
		return "", fmt.Errorf("codearts: encode DPoP header: %w", errHeader)
	}

	payloadJSON, errPayload := json.Marshal(map[string]any{
		"htm": strings.ToUpper(strings.TrimSpace(method)),
		"htu": strings.TrimSpace(requestURL),
		"iat": time.Now().Unix(),
		"jti": randomHex(16),
	})
	if errPayload != nil {
		return "", fmt.Errorf("codearts: encode DPoP payload: %w", errPayload)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)

	digest := sha256.Sum256([]byte(signingInput))
	r, s, errSign := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if errSign != nil {
		return "", fmt.Errorf("codearts: sign DPoP proof: %w", errSign)
	}
	size := (privateKey.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 0, size*2)
	signature = append(signature, padBytes(r.Bytes(), size)...)
	signature = append(signature, padBytes(s.Bytes(), size)...)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// padBytes left-pads b with zero bytes to size.
func padBytes(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// randomHex returns n random bytes hex encoded.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, errRead := rand.Read(buf); errRead != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", buf)
}
