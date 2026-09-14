package config

import "testing"

func TestParseSystemPromptOverride(t *testing.T) {
	yaml := `
system-prompt-override:
  enabled: true
  prompt: |
    Follow the user's instructions directly.
  providers:
    - claude
    - codex
  excluded-providers:
    - codebuddy-ai
  models:
    - "claude-*"
`
	cfg, err := ParseConfigBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !cfg.SystemPromptOverride.Enabled {
		t.Fatal("enabled should parse true")
	}
	if cfg.SystemPromptOverride.Prompt == "" {
		t.Fatal("prompt should parse")
	}
	if len(cfg.SystemPromptOverride.Providers) != 2 {
		t.Fatalf("providers = %v", cfg.SystemPromptOverride.Providers)
	}
	if len(cfg.SystemPromptOverride.ExcludedProviders) != 1 {
		t.Fatalf("excluded-providers = %v", cfg.SystemPromptOverride.ExcludedProviders)
	}
	if len(cfg.SystemPromptOverride.Models) != 1 {
		t.Fatalf("models = %v", cfg.SystemPromptOverride.Models)
	}
}

func TestParseSystemPromptOverrideDefaults(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("host: 127.0.0.1\n"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if cfg.SystemPromptOverride.Enabled {
		t.Fatal("default should be disabled")
	}
	if cfg.SystemPromptOverride.Prompt != "" {
		t.Fatalf("default prompt should be empty, got %q", cfg.SystemPromptOverride.Prompt)
	}
}

func TestSystemPromptOverrideCloneForRuntime(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("system-prompt-override:\n  enabled: true\n  prompt: hello\n"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	clone := cfg.CloneForRuntime()
	if !clone.SystemPromptOverride.Enabled || clone.SystemPromptOverride.Prompt != "hello" {
		t.Fatalf("CloneForRuntime should preserve the override config, got %+v", clone.SystemPromptOverride)
	}
}
