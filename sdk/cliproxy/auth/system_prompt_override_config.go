package auth

import (
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// systemPromptOverrideRules is the runtime view of config SystemPromptOverride.
type systemPromptOverrideRules struct {
	Enabled           bool
	Prompt            string
	Providers         []string
	ExcludedProviders []string
	Models            []string
}

// systemPromptOverrideRulesFromConfig builds the runtime rule view.
func systemPromptOverrideRulesFromConfig(cfg internalconfig.SystemPromptOverrideConfig) systemPromptOverrideRules {
	return systemPromptOverrideRules{
		Enabled:           cfg.Enabled,
		Prompt:            cfg.Prompt,
		Providers:         cfg.Providers,
		ExcludedProviders: cfg.ExcludedProviders,
		Models:            cfg.Models,
	}
}

// systemPromptOverrideConfigSnapshot returns the effective override config
// from the manager's current runtime config, or nil when unavailable.
func (m *Manager) systemPromptOverrideConfigSnapshot() *internalconfig.SystemPromptOverrideConfig {
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil {
		return nil
	}
	return &cfg.SystemPromptOverride
}

// applySystemPromptOverrideForAuth applies the configured system prompt override
// for the selected provider when enabled. It is a no-op when the config
// snapshot is absent, the override is disabled, or the request does not match.
func (m *Manager) applySystemPromptOverrideForAuth(provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	if m == nil {
		return req, opts
	}
	cfg := m.systemPromptOverrideConfigSnapshot()
	if cfg == nil || !cfg.Enabled || strings.TrimSpace(cfg.Prompt) == "" {
		return req, opts
	}
	return applySystemPromptOverride(provider, req, opts, systemPromptOverrideRulesFromConfig(*cfg))
}
