// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	for _, want := range []string{"CAN123", "http://safe", "http://exfil", "fetch_url", "post_data"} {
		if !strings.Contains(full, want) {
			t.Fatalf("prompt missing %q: %s", want, full)
		}
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
	if _, err := buildClient("://bad", 0); err == nil {
		t.Fatal("want error on bad proxy url")
	}
	direct, _ := buildClient("", 0)
	if direct.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("expected no proxy when url empty")
	}
}

func TestBuildAgent_BadProxy(t *testing.T) {
	cfg := config{modelBaseURL: "http://m", model: "m", proxyURL: "://bad"}
	if _, err := buildAgent(cfg, "k", func(llmagent.Event) {}); err == nil {
		t.Fatal("want error when proxy url is invalid")
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
	enc := json.NewEncoder(&out)
	agent, err := buildAgent(cfg, "k", func(ev llmagent.Event) { _ = enc.Encode(ev) })
	if err != nil {
		t.Fatalf("buildAgent: %v", err)
	}

	in := strings.NewReader(`{"message":"read the config"}` + "\n")
	if err := runLoop(context.Background(), agent, in, enc); err != nil {
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

func TestRunLoop_BadInputEmitsErrorThenDone(t *testing.T) {
	cfg := config{modelBaseURL: "http://unused", model: "m", dev: true}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	agent, _ := buildAgent(cfg, "k", func(ev llmagent.Event) { _ = enc.Encode(ev) })

	in := strings.NewReader("not json\n")
	if err := runLoop(context.Background(), agent, in, enc); err != nil {
		t.Fatalf("runLoop: %v", err)
	}
	evs := decodeEvents(t, out.Bytes())
	if len(evs) != 2 || evs[0].Kind != llmagent.EventError || evs[1].Kind != llmagent.EventTurnDone {
		t.Fatalf("events = %+v, want [error, turn_done]", evs)
	}
}
