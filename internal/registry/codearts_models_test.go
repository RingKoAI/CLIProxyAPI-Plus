package registry

import (
	"strings"
	"testing"
)

// TestGetCodeArtsModels pins the embedded catalog and its defaults.
func TestGetCodeArtsModels(t *testing.T) {
	models := GetCodeArtsModels()
	if len(models) == 0 {
		t.Fatal("codearts catalog is empty")
	}

	byID := make(map[string]*ModelInfo, len(models))
	for _, model := range models {
		byID[model.ID] = model
		if model.Type != "codearts" {
			t.Errorf("model %s type = %q, want codearts", model.ID, model.Type)
		}
		if model.OwnedBy == "" {
			t.Errorf("model %s has no owned_by", model.ID)
		}
		if model.MaxCompletionTokens <= 0 {
			t.Errorf("model %s has no max_completion_tokens", model.ID)
		}
	}

	glm52, ok := byID["GLM-5.2"]
	if !ok {
		t.Fatalf("GLM-5.2 missing from the catalog: %v", keys(byID))
	}
	if glm52.ContextLength != 202752 {
		t.Errorf("GLM-5.2 context_length = %d, want 202752", glm52.ContextLength)
	}
	if glm52.MaxCompletionTokens != 131072 {
		t.Errorf("GLM-5.2 max_completion_tokens = %d, want 131072", glm52.MaxCompletionTokens)
	}
	if glm52.Thinking == nil || len(glm52.Thinking.Levels) == 0 {
		t.Error("GLM-5.2 should advertise thinking levels")
	}

	if _, ok := byID["Auto"]; !ok {
		t.Errorf("Auto missing from the catalog: %v", keys(byID))
	}
}

// TestGetCodeArtsModelsReturnsClone pins that callers cannot mutate the catalog.
func TestGetCodeArtsModelsReturnsClone(t *testing.T) {
	first := GetCodeArtsModels()
	if len(first) == 0 {
		t.Fatal("empty catalog")
	}
	original := first[0].ID
	first[0].ID = "mutated"
	second := GetCodeArtsModels()
	if second[0].ID == "mutated" {
		t.Fatal("the catalog was mutated through a returned slice")
	}
	if second[0].ID != original {
		t.Fatalf("catalog changed: %q != %q", second[0].ID, original)
	}
}

// TestLookupCodeArtsModel pins the single-model lookup.
func TestLookupCodeArtsModel(t *testing.T) {
	if got := LookupCodeArtsModel("GLM-5.2"); got == nil || got.ID != "GLM-5.2" {
		t.Fatalf("lookup GLM-5.2 = %+v", got)
	}
	if got := LookupCodeArtsModel("  GLM-5.2  "); got == nil {
		t.Fatal("lookup should trim whitespace")
	}
	if got := LookupCodeArtsModel("does-not-exist"); got != nil {
		t.Fatalf("unexpected lookup result: %+v", got)
	}
	if got := LookupCodeArtsModel(""); got != nil {
		t.Fatalf("empty lookup should return nil, got %+v", got)
	}
}

// TestGetStaticModelDefinitionsByChannelCodeArts pins the channel routing used by
// the management model-definitions API.
func TestGetStaticModelDefinitionsByChannelCodeArts(t *testing.T) {
	models := GetStaticModelDefinitionsByChannel("codearts")
	if len(models) == 0 {
		t.Fatal("codearts channel returned no models")
	}
	for _, model := range models {
		if strings.TrimSpace(model.ID) == "" {
			t.Error("a model has an empty id")
		}
	}
	// Case-insensitive lookup must work too.
	if len(GetStaticModelDefinitionsByChannel("CodeArts")) == 0 {
		t.Fatal("channel lookup should be case-insensitive")
	}
}

// TestLookupStaticModelInfoFindsCodeArts pins the shared fallback lookup.
func TestLookupStaticModelInfoFindsCodeArts(t *testing.T) {
	if got := LookupStaticModelInfo("GLM-5.2"); got == nil || got.ID != "GLM-5.2" {
		t.Fatalf("LookupStaticModelInfo(GLM-5.2) = %+v", got)
	}
}

// TestNormalizeCodeArtsModelsDropsInvalidEntries pins normalization.
func TestNormalizeCodeArtsModelsDropsInvalidEntries(t *testing.T) {
	models := normalizeCodeArtsModels([]*ModelInfo{
		nil,
		{ID: ""},
		{ID: "  keep-me  "},
		{ID: "keep-me"}, // duplicate
	})
	if len(models) != 1 {
		t.Fatalf("normalized to %d models, want 1: %+v", len(models), models)
	}
	if models[0].ID != "keep-me" {
		t.Fatalf("id = %q, want keep-me", models[0].ID)
	}
	if models[0].Object != "model" || models[0].Type != "codearts" || models[0].OwnedBy != "huaweicloud" {
		t.Fatalf("defaults not applied: %+v", models[0])
	}
}

func keys(m map[string]*ModelInfo) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
