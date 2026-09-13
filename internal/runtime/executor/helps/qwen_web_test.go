package helps

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestQwenWebPromptPreservesRoles(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"First"},{"role":"assistant","content":"Reply"},{"role":"user","content":[{"type":"text","text":"Next"}]}]}`)
	prompt, err := QwenWebPrompt(body)
	if err != nil {
		t.Fatal(err)
	}
	var turns []struct{ Role, Content string }
	_, raw, ok := strings.Cut(prompt, "\n")
	if !ok || json.Unmarshal([]byte(raw), &turns) != nil {
		t.Fatalf("invalid transcript: %s", prompt)
	}
	if len(turns) != 4 || turns[0].Role != "system" || turns[2].Content != "Reply" || turns[3].Content != "Next\n" {
		t.Fatalf("lost history: %+v", turns)
	}
}
func TestQwenWebRejectsToolProtocols(t *testing.T) {
	for _, body := range []string{
		`{"tools":[{"type":"function"}]}`, `{"messages":[{"role":"tool","content":"x"}]}`,
		`{"messages":[{"role":"assistant","tool_calls":[{}]}]}`, `{"input":[{"type":"function_call_output"}]}`,
		`{"contents":[{"parts":[{"functionCall":{"name":"foo"}}]}]}`, `{"messages":[{"content":[{"type":"tool_use"}]}]}`,
		`{"tool_choice":"auto"}`, `{"thinking":{"type":"enabled"}}`,
	} {
		if QwenWebRejectUnsupported([]byte(body)) == nil {
			t.Errorf("accepted: %s", body)
		}
	}
	if err := QwenWebRejectUnsupported([]byte(`{"tools":[],"messages":[{"role":"user","content":"tools are not supported"}]}`)); err != nil {
		t.Fatal(err)
	}
}
func TestQwenWebRejectsNonTextAndContinuation(t *testing.T) {
	for _, body := range []string{`{"messages":[]}`, `{"messages":[{"role":"assistant","content":"prefix"}]}`, `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`} {
		if _, err := QwenWebPrompt([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}
func TestQwenWebSSE(t *testing.T) {
	input := `data: {"choices":[{"delta":{"phase":"thinking_summary","content":"plan"}}]}` + "\n\n" + `data: {"choices":[{"delta":{"phase":"answer","content":"hello","status":"finished"}}]}` + "\n\n"
	var text, reasoning string
	err := ConsumeQwenWebSSE(strings.NewReader(input), func(d QwenWebDelta) error { text += d.Text; reasoning += d.Reasoning; return nil })
	if err != nil || text != "hello" || reasoning != "plan" {
		t.Fatalf("%q %q %v", text, reasoning, err)
	}
	for _, bad := range []string{`data: {"success":false,"data":{"details":"secret-value"}}` + "\n", `data: {"choices":[{"delta":{"content":"incomplete"}}]}` + "\n", `data: not-json` + "\n"} {
		err := ConsumeQwenWebSSE(strings.NewReader(bad), func(QwenWebDelta) error { return nil })
		if err == nil || strings.Contains(err.Error(), "secret-value") {
			t.Errorf("bad stream result: %v", err)
		}
	}
}
func TestQwenWebImages(t *testing.T) {
	// Real image events carry the URL as the image_gen delta content.
	event := []byte(`{"choices":[{"delta":{"role":"assistant","content":"https://cdn.qwenlm.ai/output/u/t2i/a.png?key=k","phase":"image_gen","status":"typing"}}]}`)
	if urls := QwenWebImages(event); len(urls) != 1 || urls[0] != "https://cdn.qwenlm.ai/output/u/t2i/a.png?key=k" {
		t.Fatalf("image_gen urls=%v", urls)
	}
	// Non-image content and non-Qwen hosts are ignored to avoid SSRF and bogus results.
	for _, raw := range [][]byte{
		[]byte(`{"choices":[{"delta":{"content":"hello","phase":"answer"}}]}`),
		[]byte(`{"choices":[{"delta":{"content":"https://evil.example.com/a.png","phase":"image_gen"}}]}`),
		[]byte(`{"choices":[{"delta":{"content":"http://cdn.qwenlm.ai/a.png","phase":"image_gen"}}]}`),
		[]byte(`{"response.created":{"chat_id":"x"}}`),
	} {
		if urls := QwenWebImages(raw); len(urls) != 0 {
			t.Errorf("unexpected urls %v for %s", urls, raw)
		}
	}
}

func TestQwenWebPayloadMatchesRealWebFrontend(t *testing.T) {
	image := QwenWebPayload("chat-1", "draw", true, "16:9")
	msg := gjson.Parse(`{}`)
	_ = msg
	if image["chatId"] != "chat-1" || image["chat_id"] != "chat-1" {
		t.Fatalf("chat id fields: %v", image)
	}
	raw, _ := json.Marshal(image)
	if gjson.GetBytes(raw, "messages.0.chat_type").String() != "t2i" ||
		gjson.GetBytes(raw, "messages.0.sub_chat_type").String() != "t2i" {
		t.Fatalf("image turn kind wrong: %s", raw)
	}
	if gjson.GetBytes(raw, "messages.0.extra.meta.model").String() != QwenWebUpstreamImageModel {
		t.Fatalf("image model missing: %s", raw)
	}
	if gjson.GetBytes(raw, "size").String() != "16:9" || gjson.GetBytes(raw, "messages.0.extra.meta.size").String() != "16:9" {
		t.Fatalf("ratio missing: %s", raw)
	}
	text := QwenWebPayload("chat-1", "hi", false, "1:1")
	raw, _ = json.Marshal(text)
	if gjson.GetBytes(raw, "messages.0.chat_type").String() != "t2t" || gjson.GetBytes(raw, "size").Exists() {
		t.Fatalf("text payload wrong: %s", raw)
	}
}

func TestQwenWebSSEIgnoresControlFramesAndDetectsRiskControl(t *testing.T) {
	stream := strings.Join([]string{
		`data: {"response.created":{"chat_id":"c","response_id":"r"}}`,
		``,
		`data: {"response.info":{"action":"keep_alive"}}`,
		``,
		`data: {"choices":[{"delta":{"role":"assistant","content":"","phase":"thinking_summary","status":"typing"}}]}`,
		``,
		`data: {"choices":[{"delta":{"content":"hi","phase":"answer","status":"typing"}}]}`, //#nosec G101 -- test fixture, not a credential
		``,
		`data: {"choices":[{"delta":{"content":"","phase":"answer","status":"finished"}}]}`,
		``,
	}, "\n")
	var text, reasoning string
	if err := ConsumeQwenWebSSE(strings.NewReader(stream), func(d QwenWebDelta) error {
		text += d.Text
		reasoning += d.Reasoning
		return nil
	}); err != nil {
		t.Fatalf("control frames rejected: %v", err)
	}
	if text != "hi" {
		t.Fatalf("text = %q", text)
	}
	// Risk-control bodies arrive as HTTP 200 JSON instead of an event stream.
	risk := `data: {"ret":["FAIL_SYS_USER_VALIDATE","RGV587_ERROR::SM::x"],"data":{"url":"https://chat.qwen.ai/punish?action=captcha"}}`
	err := ConsumeQwenWebSSE(strings.NewReader(risk), func(QwenWebDelta) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatalf("risk control not reported: %v", err)
	}
}
