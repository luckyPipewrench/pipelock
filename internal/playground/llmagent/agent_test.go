// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package llmagent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// scriptedModel is a fake OpenAI-compatible endpoint that returns a fixed list
// of assistant messages, one per request, and records the request bodies so a
// test can assert what was sent (tools advertised, tool results fed back).
type scriptedModel struct {
	mu        sync.Mutex
	responses []chatMessage
	calls     int
	bodies    []completionRequest
	status    int    // override status for the next response (0 => 200)
	errorBody string // override non-200 body
	rawBody   string // override raw body (for malformed-response tests)
}

func (m *scriptedModel) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var req completionRequest
		_ = json.Unmarshal(raw, &req)
		m.bodies = append(m.bodies, req)
		idx := m.calls
		m.calls++

		if m.status != 0 {
			w.WriteHeader(m.status)
			if m.errorBody != "" {
				_, _ = io.WriteString(w, m.errorBody)
				return
			}
			_, _ = io.WriteString(w, `{"error":{"message":"boom"}}`)
			return
		}
		if m.rawBody != "" {
			_, _ = io.WriteString(w, m.rawBody)
			return
		}
		if idx >= len(m.responses) {
			// Out of script: return a plain stop so loops terminate.
			_ = json.NewEncoder(w).Encode(completionResponse{
				Choices: []struct {
					Message      chatMessage `json:"message"`
					FinishReason string      `json:"finish_reason"`
				}{{Message: chatMessage{Role: roleAssistant, Content: "done"}, FinishReason: "stop"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(completionResponse{
			Choices: []struct {
				Message      chatMessage `json:"message"`
				FinishReason string      `json:"finish_reason"`
			}{{Message: m.responses[idx]}},
		})
	}
}

func textMsg(s string) chatMessage {
	return chatMessage{Role: roleAssistant, Content: s}
}

func toolMsg(id, name, args string) chatMessage {
	return chatMessage{Role: roleAssistant, ToolCalls: []toolCall{{
		ID: id, Type: "function", Function: toolCallFunction{Name: name, Arguments: args},
	}}}
}

// collectEvents returns an emit func plus a pointer to the slice it fills.
func collectEvents() (func(Event), *[]Event) {
	var (
		mu  sync.Mutex
		evs []Event
	)
	return func(e Event) {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
	}, &evs
}

func newAgent(t *testing.T, model *scriptedModel, tools []Tool, emit func(Event)) *Agent {
	t.Helper()
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	return New(ModelConfig{BaseURL: srv.URL, Model: "test-model", APIKey: "k"}, srv.Client(), tools, emit)
}

func kinds(evs []Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

// coreKinds returns the event kinds with the framing signals (thinking, turn_end)
// stripped, so a test focused on the tool/reply flow is not coupled to the
// thinking/turn-end framing (which the dedicated signal tests cover).
func coreKinds(evs []Event) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		if e.Kind == EventThinking || e.Kind == EventTurnEnd {
			continue
		}
		out = append(out, e.Kind)
	}
	return out
}

func TestRun_PlainReply(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{textMsg("hello there")}}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	final, err := a.Run(context.Background(), "hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "hello there" {
		t.Fatalf("final = %q, want %q", final, "hello there")
	}
	if got := coreKinds(*evs); len(got) != 1 || got[0] != EventReply {
		t.Fatalf("core events = %v, want [reply]", got)
	}
	if model.calls != 1 {
		t.Fatalf("model calls = %d, want 1", model.calls)
	}
}

func TestRun_ToolCallThenReply(t *testing.T) {
	// A lab target the tool will reach. Returns 200 (allowed read).
	var toolHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toolHits++
		if got := r.Header.Get("X-Agent"); got != "lab-agent" {
			t.Errorf("agent header = %q, want lab-agent", got)
		}
		_, _ = io.WriteString(w, "lab config: ok")
	}))
	t.Cleanup(target.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url":"`+target.URL+`"}`),
		textMsg("I read the config."),
	}}
	emit, evs := collectEvents()
	tools := LabTools(http.DefaultClient, map[string]string{"X-Agent": "lab-agent"})
	a := newAgent(t, model, tools, emit)

	final, err := a.Run(context.Background(), "read the config")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "I read the config." {
		t.Fatalf("final = %q", final)
	}
	if toolHits != 1 {
		t.Fatalf("tool target hits = %d, want 1", toolHits)
	}
	// Expect the core flow: tool_call, tool_result, reply (in order). Framing
	// signals (thinking/turn_end) are covered by the dedicated signal tests.
	want := []string{EventToolCall, EventToolResult, EventReply}
	if got := coreKinds(*evs); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("core events = %v, want %v", got, want)
	}
	// The second model call must carry the tool result back.
	if model.calls != 2 {
		t.Fatalf("model calls = %d, want 2", model.calls)
	}
	last := model.bodies[1].Messages
	if last[len(last)-1].Role != roleTool || !strings.Contains(last[len(last)-1].Content, "HTTP 200") {
		t.Fatalf("tool result not fed back: %+v", last[len(last)-1])
	}
	// The tool-result event records the allowed status.
	var tr Event
	for _, e := range *evs {
		if e.Kind == EventToolResult {
			tr = e
		}
	}
	if tr.Status != http.StatusOK || tr.Note != "allowed" || tr.URL != target.URL {
		t.Fatalf("tool_result event = %+v", tr)
	}
}

func TestRun_BlockedToolStatusFedBack(t *testing.T) {
	// Simulate the proxy blocking the exfil POST with a 403.
	blocker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "blocked: body DLP")
	}))
	t.Cleanup(blocker.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolPostData, `{"url":"`+blocker.URL+`","data":"canary=AKIA_FAKE"}`),
		textMsg("It got blocked."),
	}}
	emit, evs := collectEvents()
	tools := LabTools(http.DefaultClient, nil)
	a := newAgent(t, model, tools, emit)

	final, err := a.Run(context.Background(), "send the canary")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "It got blocked." {
		t.Fatalf("final = %q", final)
	}
	var tr Event
	for _, e := range *evs {
		if e.Kind == EventToolResult {
			tr = e
		}
	}
	if tr.Status != http.StatusForbidden || tr.Note != "blocked" || tr.Method != http.MethodPost {
		t.Fatalf("blocked tool_result event = %+v", tr)
	}
}

func TestRun_UnknownToolReported(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", "delete_everything", `{}`),
		textMsg("ok, can't do that"),
	}}
	emit, evs := collectEvents()
	a := newAgent(t, model, LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "delete it all")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "ok, can't do that" {
		t.Fatalf("final = %q", final)
	}
	// The unknown tool result must be fed back so the model can recover.
	last := model.bodies[1].Messages
	if got := last[len(last)-1]; got.Role != roleTool || !strings.Contains(got.Content, "unknown tool") {
		t.Fatalf("unknown tool not reported back: %+v", got)
	}
	_ = evs
}

func TestRun_MalformedToolArgsNoPanic(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url": 123}`), // url is not a string
		textMsg("fixed it"),
	}}
	emit, _ := collectEvents()
	a := newAgent(t, model, LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "fetch")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if final != "fixed it" {
		t.Fatalf("final = %q", final)
	}
	last := model.bodies[1].Messages
	if got := last[len(last)-1]; got.Role != roleTool || !strings.Contains(got.Content, "needs a") {
		t.Fatalf("bad-args result not fed back: %+v", got)
	}
}

func TestRun_ModelHTTPErrorReturned(t *testing.T) {
	model := &scriptedModel{status: http.StatusInternalServerError}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	_, err := a.Run(context.Background(), "hi")
	if err == nil {
		t.Fatal("want error on model 500")
	}
	// A thinking signal precedes the model call; the call then errors. Expect
	// exactly [thinking, error] and no turn-end (the turn aborted on error).
	if got := kinds(*evs); strings.Join(got, ",") != EventThinking+","+EventError {
		t.Fatalf("events = %v, want [thinking error]", got)
	}
}

func TestRun_StepCapStops(t *testing.T) {
	// Model always asks for a tool, never finishes. Loop must stop at MaxSteps.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(loop.Close)

	// Build a script longer than MaxSteps, all tool calls.
	var resp []chatMessage
	for i := 0; i < 10; i++ {
		resp = append(resp, toolMsg("c", ToolFetchURL, `{"url":"`+loop.URL+`"}`))
	}
	model := &scriptedModel{responses: resp}
	emit, _ := collectEvents()
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	a := New(ModelConfig{BaseURL: srv.URL, Model: "m", MaxSteps: 3}, srv.Client(),
		LabTools(http.DefaultClient, nil), emit)

	final, err := a.Run(context.Background(), "loop")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The turn always ends with a final answer now (a forced summary), even at the
	// step cap, so a follow-up like "continue" has context. The forced summary
	// consumes one reserved model-call slot, so MaxSteps remains the total cap.
	if final == "" {
		t.Fatalf("final must be non-empty (forced summary), got empty")
	}
	if model.calls != 3 {
		t.Fatalf("model calls = %d, want 3 (MaxSteps includes forced summary)", model.calls)
	}
}

// multiToolMsg builds one assistant response carrying n tool calls -- the
// parallel-tool-call shape a single model response can emit, which MaxSteps
// alone does not bound (all n would run in one step without a tool-call cap).
func multiToolMsg(name, args string, n int) chatMessage {
	calls := make([]toolCall, n)
	for i := range calls {
		calls[i] = toolCall{ID: "c", Type: "function", Function: toolCallFunction{Name: name, Arguments: args}}
	}
	return chatMessage{Role: roleAssistant, ToolCalls: calls}
}

func TestRun_ToolCallCapStopsWithinOneResponse(t *testing.T) {
	// One model response carries 10 tool calls; the per-turn cap must stop after
	// MaxToolCalls real outbound requests rather than running all ten.
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)

	model := &scriptedModel{responses: []chatMessage{
		multiToolMsg(ToolFetchURL, `{"url":"`+target.URL+`"}`, 10),
	}}
	emit, evs := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxToolCalls: 3})

	final, err := a.Run(context.Background(), "spray tool calls")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The cap still limits real outbound requests to 3; the turn then ends with a
	// forced tool-less summary (the scriptedModel's out-of-script "done").
	if final != "done" {
		t.Fatalf("final = %q, want %q (forced summary after the cap)", final, "done")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("tool target hits = %d, want 3 (MaxToolCalls cap)", got)
	}
	sawFinal := false
	for _, e := range *evs {
		if e.Kind == EventReply && e.Text == "done" {
			sawFinal = true
		}
	}
	if !sawFinal {
		t.Error("missing forced final-summary reply event")
	}
}

func TestRun_MalformedModelResponse(t *testing.T) {
	model := &scriptedModel{rawBody: "not json"}
	emit, _ := collectEvents()
	a := newAgent(t, model, nil, emit)
	if _, err := a.Run(context.Background(), "hi"); err == nil {
		t.Fatal("want decode error on malformed model response")
	}
}

func TestRun_DuplicateModelResponseRejected(t *testing.T) {
	model := &scriptedModel{rawBody: `{"choices":[{"message":{"role":"assistant","content":"safe"}}],"choices":[{"message":{"role":"assistant","content":"unsafe"}}]}`}
	emit, _ := collectEvents()
	a := newAgent(t, model, nil, emit)
	if _, err := a.Run(context.Background(), "hi"); err == nil {
		t.Fatal("want duplicate-key error on ambiguous model response")
	}
}

// newAgentCfg builds an agent against a scripted model with an explicit config
// (so memory/step settings can be exercised) and returns it.
func newAgentCfg(t *testing.T, model *scriptedModel, tools []Tool, emit func(Event), cfg ModelConfig) *Agent {
	t.Helper()
	srv := httptest.NewServer(model.handler())
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	if cfg.Model == "" {
		cfg.Model = "test-model"
	}
	cfg.APIKey = "k"
	return New(cfg, srv.Client(), tools, emit)
}

// roleSeq returns the role of each message, for compact assertions.
func roleSeq(msgs []chatMessage) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.Role
	}
	return out
}

func TestComplete_SetsMaxTokens(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{textMsg("ok")}}
	emit, _ := collectEvents()
	a := newAgent(t, model, nil, emit) // default config
	if _, err := a.Run(context.Background(), "hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := model.bodies[0].MaxTokens; got != defaultMaxResponseTokens {
		t.Fatalf("default max_tokens = %d, want %d", got, defaultMaxResponseTokens)
	}

	model2 := &scriptedModel{responses: []chatMessage{textMsg("ok")}}
	a2 := newAgentCfg(t, model2, nil, emit, ModelConfig{MaxResponseTokens: 256})
	if _, err := a2.Run(context.Background(), "hi"); err != nil {
		t.Fatalf("Run (custom): %v", err)
	}
	if got := model2.bodies[0].MaxTokens; got != 256 {
		t.Fatalf("custom max_tokens = %d, want 256", got)
	}
}

func TestRun_EmitsThinkingThenTurnEndComplete(t *testing.T) {
	// A plain-reply turn must emit a thinking signal BEFORE the model answers (so
	// the UI shows "thinking" exactly, not by guessing) and a turn-end signal with
	// reason "complete" when the model finishes on its own.
	model := &scriptedModel{responses: []chatMessage{textMsg("all done")}}
	emit, evs := collectEvents()
	a := newAgent(t, model, nil, emit)

	if _, err := a.Run(context.Background(), "hi"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := kinds(*evs)
	// thinking must come before the reply.
	thinkIdx, replyIdx, endIdx := -1, -1, -1
	for i, k := range got {
		switch k {
		case EventThinking:
			if thinkIdx == -1 {
				thinkIdx = i
			}
		case EventReply:
			replyIdx = i
		case EventTurnEnd:
			endIdx = i
		}
	}
	if thinkIdx == -1 || replyIdx == -1 || thinkIdx > replyIdx {
		t.Fatalf("expected a thinking event before the reply, events = %v", got)
	}
	if endIdx == -1 {
		t.Fatalf("expected a turn-end event, events = %v", got)
	}
	if r := (*evs)[endIdx].Reason; r != turnEndComplete {
		t.Fatalf("turn-end reason = %q, want %q", r, turnEndComplete)
	}
}

func TestRun_TurnEndReason_ToolCallCap(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)
	model := &scriptedModel{responses: []chatMessage{
		multiToolMsg(ToolFetchURL, `{"url":"`+target.URL+`"}`, 5),
	}}
	emit, evs := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxToolCalls: 2})
	if _, err := a.Run(context.Background(), "spray"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := lastTurnEndReason(*evs); got != turnEndToolCallLimit {
		t.Fatalf("turn-end reason = %q, want %q", got, turnEndToolCallLimit)
	}
}

func TestRun_TurnEndReason_StepCap(t *testing.T) {
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(loop.Close)
	var resp []chatMessage
	for i := 0; i < 10; i++ {
		resp = append(resp, toolMsg("c", ToolFetchURL, `{"url":"`+loop.URL+`"}`))
	}
	model := &scriptedModel{responses: resp}
	emit, evs := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxSteps: 2})
	if _, err := a.Run(context.Background(), "loop"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := lastTurnEndReason(*evs); got != turnEndStepLimit {
		t.Fatalf("turn-end reason = %q, want %q", got, turnEndStepLimit)
	}
}

func lastTurnEndReason(evs []Event) string {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == EventTurnEnd {
			return evs[i].Reason
		}
	}
	return ""
}

func TestRun_NoHistoryByDefault(t *testing.T) {
	// MaxHistoryTurns unset (0): each Run is independent, no prior turn replayed.
	model := &scriptedModel{responses: []chatMessage{textMsg("one"), textMsg("two")}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, nil, emit, ModelConfig{})

	if _, err := a.Run(context.Background(), "first"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := a.Run(context.Background(), "second"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	// The second request must carry only system + the new user message.
	got := roleSeq(model.bodies[1].Messages)
	if strings.Join(got, ",") != roleSystem+","+roleUser {
		t.Fatalf("second request roles = %v, want [system user] (no memory)", got)
	}
	if model.bodies[1].Messages[1].Content != "second" {
		t.Fatalf("second request user = %q, want %q", model.bodies[1].Messages[1].Content, "second")
	}
}

func TestRun_HistoryReplayedAcrossTurns(t *testing.T) {
	model := &scriptedModel{responses: []chatMessage{textMsg("reply one"), textMsg("reply two")}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, nil, emit, ModelConfig{MaxHistoryTurns: 8})

	if _, err := a.Run(context.Background(), "first"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := a.Run(context.Background(), "second"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	// The second request replays the first turn: system, prior user, prior
	// assistant reply, then the new user message.
	msgs := model.bodies[1].Messages
	if got := strings.Join(roleSeq(msgs), ","); got != strings.Join([]string{roleSystem, roleUser, roleAssistant, roleUser}, ",") {
		t.Fatalf("second request roles = %v", roleSeq(msgs))
	}
	if msgs[1].Content != "first" || msgs[2].Content != "reply one" || msgs[3].Content != "second" {
		t.Fatalf("history not replayed correctly: %+v", msgs)
	}
}

func TestRun_ContextCarriesToolDataAcrossTurns(t *testing.T) {
	// P1: the agent must hold TRUE conversational continuity -- turn 2 carries
	// forward the full working context from turn 1, including the assistant's tool
	// call AND the tool result (what the agent explored), so the model does not
	// re-discover the filesystem from zero every turn (the "reset" Josh feels).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "lab config: ok")
	}))
	t.Cleanup(target.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url":"`+target.URL+`"}`),
		textMsg("I read the config."),
		textMsg("Nothing else to do."),
	}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxHistoryTurns: 8})

	if _, err := a.Run(context.Background(), "read the config"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := a.Run(context.Background(), "anything else?"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	// Turn 2 is the third model call (turn 1 used two: tool, then reply). It must
	// replay the full turn-1 context: system, user, assistant(tool_calls), tool
	// result, assistant reply, then the new user message.
	msgs := model.bodies[2].Messages
	wantRoles := []string{roleSystem, roleUser, roleAssistant, roleTool, roleAssistant, roleUser}
	if got := strings.Join(roleSeq(msgs), ","); got != strings.Join(wantRoles, ",") {
		t.Fatalf("turn-2 roles = %v, want %v", roleSeq(msgs), wantRoles)
	}
	sawToolCall, sawToolResult := false, false
	for _, m := range msgs {
		if len(m.ToolCalls) > 0 {
			sawToolCall = true
		}
		if m.Role == roleTool && strings.Contains(m.Content, "HTTP 200") {
			sawToolResult = true
		}
	}
	if !sawToolCall {
		t.Fatal("turn-2 context dropped the prior tool call (no continuity)")
	}
	if !sawToolResult {
		t.Fatal("turn-2 context dropped the prior tool result (the explored state)")
	}
	// The context must stay valid for the chat-completions API.
	assertToolPairingValid(t, msgs)
}

// assertToolPairingValid checks the chat-completions tool-message invariants:
// every tool message answers a tool_call from an EARLIER assistant message, and
// every assistant tool_call is answered by a later tool message. A context that
// violates either is rejected by the API (400), so any trimming/capping path must
// preserve both.
func assertToolPairingValid(t *testing.T, msgs []chatMessage) {
	t.Helper()
	seenCallIDs := map[string]bool{}
	answered := map[string]bool{}
	for _, m := range msgs {
		for _, tc := range m.ToolCalls {
			seenCallIDs[tc.ID] = true
		}
		if m.Role == roleTool {
			if !seenCallIDs[m.ToolCallID] {
				t.Fatalf("orphan tool message: tool_call_id %q has no earlier assistant tool_call", m.ToolCallID)
			}
			answered[m.ToolCallID] = true
		}
	}
	for id := range seenCallIDs {
		if !answered[id] {
			t.Fatalf("unanswered tool_call %q: no tool message responds to it", id)
		}
	}
}

func TestRun_ToolCallCapKeepsContextValid(t *testing.T) {
	// When one assistant response carries more tool calls than the per-turn cap,
	// the loop stops executing after the cap -- but the persisted context must
	// still answer EVERY tool_call id (real result for executed calls, a synthetic
	// "skipped" result for the rest), or the next turn's request is invalid.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)

	// One assistant message with 4 distinct tool-call IDs; cap allows only 2.
	calls := make([]toolCall, 4)
	for i := range calls {
		calls[i] = toolCall{
			ID:       fmt.Sprintf("call-%d", i),
			Type:     "function",
			Function: toolCallFunction{Name: ToolFetchURL, Arguments: `{"url":"` + target.URL + `"}`},
		}
	}
	model := &scriptedModel{responses: []chatMessage{
		{Role: roleAssistant, ToolCalls: calls},
		// turn 2 plain reply
		textMsg("second turn"),
	}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxHistoryTurns: 8, MaxToolCalls: 2})

	if _, err := a.Run(context.Background(), "spray"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := a.Run(context.Background(), "next"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	// The turn-2 request carries the persisted turn-1 context; it must answer all
	// four tool calls so the API would accept it.
	assertToolPairingValid(t, model.bodies[len(model.bodies)-1].Messages)
}

func TestRun_ForceFinalAnswerSyntheticPromptNotPersisted(t *testing.T) {
	// forceFinalAnswer appends a synthetic "you hit the limit" USER message just
	// for the summary completion. That synthetic prompt must NOT be persisted as a
	// turn, or it pollutes context and miscounts turn boundaries. After a capped
	// turn 1 and a plain turn 2, the turn-2 request must contain exactly two user
	// messages (turn-1 visitor msg + turn-2 visitor msg), never the synthetic one.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(loop.Close)

	model := &scriptedModel{responses: []chatMessage{
		toolMsg("c1", ToolFetchURL, `{"url":"`+loop.URL+`"}`),
		textMsg("forced summary"), // the forced tool-less completion
		textMsg("turn two reply"),
	}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, LabTools(http.DefaultClient, nil), emit, ModelConfig{MaxHistoryTurns: 8, MaxSteps: 2})

	if _, err := a.Run(context.Background(), "go forever"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if _, err := a.Run(context.Background(), "now this"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	msgs := model.bodies[len(model.bodies)-1].Messages
	users := 0
	for _, m := range msgs {
		if m.Role == roleUser {
			users++
		}
		if m.Role == roleUser && strings.Contains(m.Content, "action limit") {
			t.Fatalf("synthetic limit prompt leaked into persisted context: %q", m.Content)
		}
	}
	if users != 2 {
		t.Fatalf("turn-2 context has %d user messages, want 2 (no synthetic turn): %v", users, roleSeq(msgs))
	}
	assertToolPairingValid(t, msgs)
}

func TestRun_ContextBoundedByTokens(t *testing.T) {
	// With a tight token budget (and no turn cap), the oldest whole turn is dropped
	// once the working context exceeds the budget -- the handoff's "bound by total
	// tokens" requirement. Memory is enabled by the token budget alone.
	// Distinctive markers (not substrings of the system prompt) so the assertion
	// targets turn content, not the always-kept system message.
	big := strings.Repeat("z", 600) // ~150 estimated tokens of reply text
	model := &scriptedModel{responses: []chatMessage{
		textMsg("REPLY_ALPHA " + big),
		textMsg("REPLY_BETA " + big),
		textMsg("REPLY_GAMMA " + big),
	}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, nil, emit, ModelConfig{MaxHistoryTokens: 60})

	for _, msg := range []string{"MSG_FIRST", "MSG_SECOND", "MSG_THIRD"} {
		if _, err := a.Run(context.Background(), msg); err != nil {
			t.Fatalf("run %q: %v", msg, err)
		}
	}
	// The third request must have dropped the oldest turn: its visitor message and
	// reply are gone.
	msgs := model.bodies[2].Messages
	for _, m := range msgs {
		if strings.Contains(m.Content, "REPLY_ALPHA") {
			t.Fatalf("token budget did not drop the oldest reply: %q", m.Content)
		}
		if m.Content == "MSG_FIRST" {
			t.Fatalf("token budget did not drop the oldest user turn: %v", roleSeq(msgs))
		}
	}
	// It must still carry the most recent prior turn (continuity is not destroyed).
	if len(msgs) < 2 || msgs[0].Role != roleSystem {
		t.Fatalf("trimmed context malformed: %v", roleSeq(msgs))
	}
}

func TestRun_HistoryBounded(t *testing.T) {
	// Keep only the last 2 turns. After four turns, the oldest turn must be gone.
	model := &scriptedModel{responses: []chatMessage{textMsg("r1"), textMsg("r2"), textMsg("r3"), textMsg("r4")}}
	emit, _ := collectEvents()
	a := newAgentCfg(t, model, nil, emit, ModelConfig{MaxHistoryTurns: 2})

	for _, msg := range []string{"t1", "t2", "t3", "t4"} {
		if _, err := a.Run(context.Background(), msg); err != nil {
			t.Fatalf("run %q: %v", msg, err)
		}
	}
	// The fourth request replays the last 2 completed turns (t2, t3) + the new
	// user (t4): system, u:t2, a:r2, u:t3, a:r3, u:t4 = 6 messages, no t1/r1.
	msgs := model.bodies[3].Messages
	if len(msgs) != 6 {
		t.Fatalf("fourth request has %d messages, want 6: %+v", len(msgs), roleSeq(msgs))
	}
	for _, m := range msgs {
		if m.Content == "t1" || m.Content == "r1" {
			t.Fatalf("bounded history still carried the oldest turn: %+v", msgs)
		}
	}
}
