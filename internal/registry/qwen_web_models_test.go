package registry

import "testing"

func TestQwenWebModelsAreIndependentAndNoTools(t *testing.T) {
	models := GetQwenWebModels()
	if len(models) != 2 || models[0].ID != "qwen-web-chat" || models[1].ID != "qwen-web-image" || models[1].Type != OpenAIImageModelType {
		t.Fatalf("unexpected models: %+v", models)
	}
	for _, m := range models {
		if m.OwnedBy != "qwen-web" || m.Thinking != nil {
			t.Fatalf("unexpected capability: %+v", m)
		}
	}
	models[0].ID = "mutated"
	if GetQwenWebModels()[0].ID != "qwen-web-chat" {
		t.Fatal("shared model mutation")
	}
}
