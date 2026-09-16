package registry

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// The CodeArts catalog is embedded from a dedicated file rather than the shared
// models/models.json.
//
// The shared catalog is replaced wholesale by StartModelsUpdater when it fetches
// the upstream catalog, and that upstream payload does not carry a codearts
// section. Keeping the models here means a remote refresh can never erase this
// provider's catalog.
//
//go:embed models/codearts_models.json
var embeddedCodeArtsModelsJSON []byte

// codeArtsModelsFilePayload mirrors the on-disk shape.
type codeArtsModelsFilePayload struct {
	CodeArts []*ModelInfo `json:"codearts,omitempty"`
	Models   []*ModelInfo `json:"models,omitempty"`
}

type codeArtsModelsStore struct {
	mu     sync.RWMutex
	models []*ModelInfo
}

var codeArtsCatalogStore = &codeArtsModelsStore{}

func init() {
	if _, errLoad := loadCodeArtsModelsFromBytes(embeddedCodeArtsModelsJSON, "embed"); errLoad != nil {
		log.Warnf("registry: failed to parse embedded codearts_models.json: %v", errLoad)
	}
}

// loadCodeArtsModelsFromBytes installs a catalog parsed from raw JSON.
func loadCodeArtsModelsFromBytes(data []byte, source string) ([]*ModelInfo, error) {
	var payload codeArtsModelsFilePayload
	if errUnmarshal := json.Unmarshal(data, &payload); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	models := payload.CodeArts
	if len(models) == 0 {
		models = payload.Models
	}
	normalized := normalizeCodeArtsModels(models)
	codeArtsCatalogStore.mu.Lock()
	codeArtsCatalogStore.models = normalized
	codeArtsCatalogStore.mu.Unlock()
	log.Debugf("registry: loaded %d codearts models from %s", len(normalized), source)
	return cloneModelInfos(normalized), nil
}

// normalizeCodeArtsModels fills defaults and drops unusable entries.
func normalizeCodeArtsModels(models []*ModelInfo) []*ModelInfo {
	out := make([]*ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		model.ID = id
		if strings.TrimSpace(model.Type) == "" {
			model.Type = "codearts"
		}
		if strings.TrimSpace(model.Object) == "" {
			model.Object = "model"
		}
		if strings.TrimSpace(model.OwnedBy) == "" {
			model.OwnedBy = "huaweicloud"
		}
		out = append(out, model)
	}
	return out
}

// staticCodeArtsModels is the fallback catalog used when the embedded file cannot
// be parsed. The values mirror the desktop client's hard-coded KERNEL_MODELS and
// the platform catalog defaults (all served by the inferhub-provider).
var staticCodeArtsModels = []*ModelInfo{
	{
		ID: "GLM-5.2", Object: "model", OwnedBy: "huaweicloud",
		Type: "codearts", DisplayName: "GLM-5.2",
		Description:   "CodeArts deep-reasoning model for complex tasks",
		ContextLength: 202752, MaxCompletionTokens: 131072,
		Thinking: &ThinkingSupport{ZeroAllowed: true, Levels: []string{"low", "medium", "high"}},
	},
	{
		ID: "GLM-5.1", Object: "model", OwnedBy: "huaweicloud",
		Type: "codearts", DisplayName: "GLM-5.1",
		Description:   "CodeArts general-purpose model for everyday coding",
		ContextLength: 202752, MaxCompletionTokens: 131072,
	},
	{
		ID: "GLM-5.2-ZX", Object: "model", OwnedBy: "huaweicloud",
		Type: "codearts", DisplayName: "GLM-5.2-ZX",
		Description:   "CodeArts priority channel with lower latency",
		ContextLength: 202752, MaxCompletionTokens: 131072,
		Thinking: &ThinkingSupport{ZeroAllowed: true, Levels: []string{"low", "medium", "high"}},
	},
	{
		ID: "Auto", Object: "model", OwnedBy: "huaweicloud",
		Type: "codearts", DisplayName: "Auto",
		Description:   "Automatically route to the most suitable model",
		ContextLength: 131072, MaxCompletionTokens: 65536,
	},
}

// GetCodeArtsModels returns the Huawei Cloud CodeArts catalog.
func GetCodeArtsModels() []*ModelInfo {
	codeArtsCatalogStore.mu.RLock()
	models := codeArtsCatalogStore.models
	codeArtsCatalogStore.mu.RUnlock()
	if len(models) > 0 {
		return cloneModelInfos(models)
	}
	return cloneModelInfos(staticCodeArtsModels)
}

// LookupCodeArtsModel resolves one model from the embedded catalog.
func LookupCodeArtsModel(modelID string) *ModelInfo {
	clean := strings.TrimSpace(modelID)
	if clean == "" {
		return nil
	}
	codeArtsCatalogStore.mu.RLock()
	defer codeArtsCatalogStore.mu.RUnlock()
	for _, model := range codeArtsCatalogStore.models {
		if model != nil && model.ID == clean {
			return model
		}
	}
	return nil
}
