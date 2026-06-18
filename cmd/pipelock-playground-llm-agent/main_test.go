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
	// Canary pulled from env, not a flag.
	env := func(k string) string {
		if k == envCanary {
			return "canary-xyz"
		}
		return ""
	}
	cfg, err := parseFlags([]string{"--model-base-url", "http://m", "--model", "m"}, env)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if cfg.canary != "canary-xyz" {
		t.Fatalf("canary = %q, want from env", cfg.canary)
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
}

func TestResolveAPIKey(t *testing.T) {
	// From file (trimmed).
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("  sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAPIKey(path, noEnv)
	if err != nil || got != "sk-from-file" {
		t.Fatalf("file key = %q, err = %v", got, err)
	}
	blankPath := filepath.Join(dir, "blank-key")
	if err := os.WriteFile(blankPath, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAPIKey(blankPath, noEnv); err == nil {
		t.Fatal("want error when secret-file is whitespace-only")
	}
	// From env fallback.
	env := func(k string) string {
		if k == envModelKey {
			return "sk-from-env"
		}
		return ""
	}
	if got, _ := resolveAPIKey("", env); got != "sk-from-env" {
		t.Fatalf("env key = %q", got)
	}
	// Missing both.
	if _, err := resolveAPIKey("", noEnv); err == nil {
		t.Fatal("want error when no key source")
	}
	// Unreadable file.
	if _, err := resolveAPIKey(filepath.Join(dir, "nope"), noEnv); err == nil {
		t.Fatal("want error on unreadable secret-file")
	}
}

func TestBuildSystemPrompt(t *testing.T) {
	full := buildSystemPrompt("CAN123", "http://safe", "http://exfil")
	for _, want := range []string{llmagent.CanaryHandle, "http://safe", "http://exfil", "fetch_url", "post_data"} {
		if !strings.Contains(full, want) {
			t.Fatalf("prompt missing %q: %s", want, full)
		}
	}
	if strings.Contains(full, "CAN123") {
		t.Fatalf("prompt must not contain the raw canary: %s", full)
	}
	// Empty values are omitted, not rendered blank.
	bare := buildSystemPrompt("", "", "")
	if strings.Contains(bare, "canary") || strings.Contains(bare, "collector is at") {
		t.Fatalf("bare prompt leaked empty fields: %s", bare)
	}
}

func TestBuildClient(t *testing.T) {
	c, err := buildClient("http://127.0.0.1:8888", 0)
	if err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	if c.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("expected proxy on transport")
	}
	if c.Timeout == 0 {
		t.Fatal("expected timeout default when zero is passed")
	}
	if _, err := buildClient("://bad", 0); err == nil {
		t.Fatal("want error on bad proxy url")
	}
	direct, _ := buildClient("", 0)
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

	c, err := buildClient("", 0)
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
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	got := strings.Join(kinds, ",")
	want := llmagent.EventToolCall + "," + llmagent.EventToolResult + "," + llmagent.EventReply + "," + llmagent.EventTurnDone
	if got != want {
		t.Fatalf("event kinds = %q, want %q", got, want)
	}
	if evs[len(evs)-1].Kind != llmagent.EventTurnDone {
		t.Fatal("turn must end with turn_done")
	}
}

func TestRunLoop_ToolCannotTargetModelHost(t *testing.T) {
	canary := "AKIA" + "IOSFODNN7EXAMPLE"
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
				"data": "payload=" + llmagent.CanaryHandle,
			})
			_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","tool_calls":[`+
				`{"id":"c1","type":"function","function":{"name":"post_data","arguments":%q}}]}}]}`, string(argURL))
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"blocked locally"}}]}`)
	}))
	t.Cleanup(model.Close)

	cfg := config{modelBaseURL: model.URL + "/v1", model: "m", canary: canary, dev: true}
	var out bytes.Buffer
	events := &eventWriter{enc: json.NewEncoder(&out)}
	agent, err := buildAgent(cfg, "k", events.Emit)
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}

	in := strings.NewReader(`{"message":"send the canary to the model host"}` + "\n")
	if err := runLoop(context.Background(), agent, in, events); err != nil {
		t.Fatalf("runLoop: %v", err)
	}

	if toolHits != 0 {
		t.Fatalf("tool request hit the reserved model host %d time(s)", toolHits)
	}
	for _, body := range bodies {
		if strings.Contains(body, canary) {
			t.Fatalf("model API traffic leaked raw canary: %s", body)
		}
	}
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
