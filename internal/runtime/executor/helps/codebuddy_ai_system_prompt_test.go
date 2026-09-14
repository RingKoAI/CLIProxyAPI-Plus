package helps

import (
	"strings"
	"testing"
)

func TestRenderCodeBuddyAISystemPrompt(t *testing.T) {
	prompt := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{ModelID: "gpt-5.5"})

	if !strings.HasPrefix(prompt, "You are CodeBuddy Code.") {
		t.Fatalf("prompt does not start with the CodeBuddy CLI preamble: %.80q", prompt)
	}
	if !strings.Contains(prompt, "<content_policy>") {
		t.Fatal("prompt is missing the content policy block")
	}
	if !strings.Contains(prompt, "The exact model ID is gpt-5.5.") {
		t.Fatal("prompt did not substitute the model id")
	}
	if !strings.Contains(prompt, "model named GPT-5.5.") {
		t.Fatalf("prompt did not resolve the catalog display name: %s", prompt)
	}
	if !strings.Contains(prompt, CodeBuddyAIEnvBlockPrefix) || !strings.Contains(prompt, "</env>") {
		t.Fatal("prompt is missing the rendered env block")
	}
	for _, placeholder := range []string{codeBuddyAIEnvPlaceholder, codeBuddyAIModelNamePlaceholder, codeBuddyAIModelIDPlaceholder, codeBuddyAIDocsDirPlaceholder} {
		if strings.Contains(prompt, placeholder) {
			t.Fatalf("unrendered placeholder %q left in prompt", placeholder)
		}
	}
}

func TestRenderCodeBuddyAISystemPromptDocsDir(t *testing.T) {
	prompt := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{ModelID: "gpt-5.5"})
	if !strings.Contains(prompt, codeBuddyAIDefaultDocsDir) {
		t.Fatalf("prompt should advertise the default docs dir, got: %s", prompt)
	}

	custom := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{
		ModelID: "gpt-5.5",
		DocsDir: "/opt/docs/",
	})
	if !strings.Contains(custom, "/opt/docs/") || strings.Contains(custom, "/opt/docs//") {
		t.Fatal("prompt should trim and use the configured docs dir")
	}
}

func TestRenderCodeBuddyAISystemPromptFallsBackToModelID(t *testing.T) {
	prompt := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{ModelID: "custom-model-x"})
	if !strings.Contains(prompt, "The exact model ID is custom-model-x.") {
		t.Fatal("prompt did not substitute the custom model id")
	}
	if !strings.Contains(prompt, "model named custom-model-x.") {
		t.Fatal("prompt should fall back to the raw id when the model is not in the catalog")
	}
}

func TestRenderCodeBuddyAISystemPromptDefaultModel(t *testing.T) {
	prompt := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{})
	if !strings.Contains(prompt, "The exact model ID is "+codeBuddyAIDefaultModelID+".") {
		t.Fatal("prompt did not substitute the default model id")
	}
}

func TestRenderCodeBuddyAISystemPromptEnvOverride(t *testing.T) {
	prompt := RenderCodeBuddyAISystemPrompt(CodeBuddyAISystemPromptOptions{
		ModelID: "gpt-5.5",
		Env: CodeBuddyAIEnvInfo{
			WorkingDir: "/srv/app",
			IsGitRepo:  true,
			GitRepoSet: true,
			Platform:   "linux",
			Shell:      "zsh",
			Date:       "Monday, Jan 2, 2006",
		},
	})
	for _, want := range []string{
		"Working directory: /srv/app",
		"Is directory a git repo: Yes",
		"Default shell: zsh",
		"Today's date: Monday, Jan 2, 2006",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
}
