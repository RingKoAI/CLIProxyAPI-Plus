package registry

// GetQwenWebModels exposes separate web-only identities, avoiding collisions
// with official Qwen API models. The upstream model was listed publicly by
// chat.qwen.ai/api/v2/models/ with both t2t and t2i capabilities.
func GetQwenWebModels() []*ModelInfo {
	return []*ModelInfo{
		{ID: "qwen-web-chat", Object: "model", OwnedBy: "qwen-web", Type: "qwen-web", DisplayName: "Qwen Web Chat", Description: "Qwen3.7-Plus web text chat; no tool calling", SupportedInputModalities: []string{"text"}, SupportedOutputModalities: []string{"text"}},
		{ID: "qwen-web-image", Object: "model", OwnedBy: "qwen-web", Type: OpenAIImageModelType, DisplayName: "Qwen Web Image", Description: "Qwen web image generation; URL output only", SupportedInputModalities: []string{"text"}, SupportedOutputModalities: []string{"image"}},
	}
}
