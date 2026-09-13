package executor

import (
	"testing"

	"github.com/tidwall/gjson"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCodeBuddyAIExecutorIdentifier(t *testing.T) {
	executor := NewCodeBuddyAIExecutor(nil)
	if got := executor.Identifier(); got != constant.CodeBuddyAI {
		t.Fatalf("Identifier() = %q, want %q", got, constant.CodeBuddyAI)
	}
}

func TestPrepareCodeBuddyAIAuthUsesOAuthTokenAndDefaults(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Provider: constant.CodeBuddyAI,
		Metadata: map[string]any{
			"access_token": "cbai-oauth",
		},
		Attributes: map[string]string{
			"header:X-IDE-Name": "custom-client",
		},
	}
	prepared := prepareCodeBuddyAuth(auth, codeBuddyAIAuthDefaults)
	if prepared == auth {
		t.Fatal("prepareCodeBuddyAuth returned original auth")
	}
	if got := prepared.Attributes["api_key"]; got != "cbai-oauth" {
		t.Fatalf("api_key = %q", got)
	}
	if got := prepared.Attributes["base_url"]; got != "https://www.codebuddy.ai/v2" {
		t.Fatalf("base_url = %q", got)
	}
	if got := prepared.Attributes["header:X-IDE-Name"]; got != "custom-client" {
		t.Fatalf("custom X-IDE-Name = %q", got)
	}
	if got := prepared.Attributes["header:X-Product"]; got != "SaaS" {
		t.Fatalf("X-Product = %q", got)
	}
	if _, ok := auth.Attributes["api_key"]; ok {
		t.Fatal("original auth was mutated")
	}
}

func TestApplyCodeBuddyAIOutgoingTransformsForcesStream(t *testing.T) {
	got := applyCodeBuddyAIOutgoingTransforms(nil, nil, "gpt-5.5", cliproxyexecutor.Options{}, []byte(`{"model":"gpt-5.5"}`))
	if !gjson.GetBytes(got, "stream").Bool() {
		t.Fatalf("stream should be forced true, got body=%s", got)
	}
}
