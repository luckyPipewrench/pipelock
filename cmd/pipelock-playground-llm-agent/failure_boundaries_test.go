// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestParseFlagsRejectsMalformedArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"--not-a-real-flag"}, want: "flag provided but not defined"},
		{name: "missing model", args: []string{"--model-base-url", "https://model.example/v1"}, want: "are required"},
		{
			name: "safe url credentials",
			args: []string{
				"--model-base-url", "https://model.example/v1",
				"--model", "demo",
				"--safe-url", "https://user:password@safe.example/config",
			},
			want: "--safe-url",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseFlags(tc.args, noEnv)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseFlags() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolveSecretValuesIgnoresEmptyNamesAndValues(t *testing.T) {
	t.Parallel()

	env := map[string]string{ // #nosec G101 -- explicit fake values exercise secret filtering.
		envSecretEnv: " , FIRST, EMPTY, , SECOND ",
		"FIRST":      " first-value ",
		"EMPTY":      " \t",
		"SECOND":     "second-value",
	}
	got := resolveSecretValues(func(name string) string { return env[name] })
	if strings.Join(got, ",") != "first-value,second-value" {
		t.Fatalf("resolveSecretValues() = %q", got)
	}
	if got := resolveSecretValues(noEnv); got != nil {
		t.Fatalf("resolveSecretValues(empty) = %q, want nil", got)
	}
}

func TestResolveAPIKeyRejectsUnreadableDescriptor(t *testing.T) {
	t.Parallel()

	_, err := resolveAPIKey(1<<20, "", noEnv)
	if err == nil || !strings.Contains(err.Error(), "read --secret-fd") {
		t.Fatalf("resolveAPIKey() error = %v, want descriptor read failure", err)
	}
}

func TestBuildAgentRejectsMalformedModelEndpoint(t *testing.T) {
	t.Parallel()

	cfg := config{modelBaseURL: "http://", model: "demo"}
	if _, err := buildAgent(cfg, "key", func(llmagent.Event) {}); err == nil || !strings.Contains(err.Error(), "model base url") {
		t.Fatalf("buildAgent() error = %v", err)
	}
}

func TestBuildClientConfiguresProxyIdentity(t *testing.T) {
	t.Parallel()

	client, err := buildClient("https://proxy.example", 0, "demo-agent")
	if err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	tr := client.Transport.(*http.Transport)
	if got := tr.ProxyConnectHeader.Get(proxy.AgentHeader); got != "demo-agent" {
		t.Fatalf("proxy actor header = %q", got)
	}
	if tr.DialContext == nil {
		t.Fatal("proxy client has no guarded dialer")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://next.example", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := client.CheckRedirect(req, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect error = %v, want ErrUseLastResponse", err)
	}
}

func TestRunLoopHandlesBlankAndOversizedInput(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	out := &eventWriter{enc: json.NewEncoder(&output)}
	if err := runLoop(context.Background(), nil, strings.NewReader("{}\n"), out); err != nil {
		t.Fatalf("blank input: %v", err)
	}
	events := decodeEvents(t, output.Bytes())
	if len(events) != 1 || events[0].Kind != llmagent.EventTurnDone {
		t.Fatalf("blank input events = %+v", events)
	}

	output.Reset()
	out = &eventWriter{enc: json.NewEncoder(&output)}
	oversized := strings.Repeat("x", maxInputLine+1) + "\n"
	err := runLoop(context.Background(), nil, strings.NewReader(oversized), out)
	if err == nil || !strings.Contains(err.Error(), "token too long") {
		t.Fatalf("oversized input error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("oversized input produced output: %q", output.String())
	}
}

func TestRunLoopFailsImmediatelyAfterPriorOutputFailure(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("parent output closed")
	out := &eventWriter{
		enc: json.NewEncoder(&bytes.Buffer{}),
		err: writeErr,
	}
	err := runLoop(context.Background(), nil, strings.NewReader("{}\n"), out)
	if err == nil || !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "write event") {
		t.Fatalf("runLoop() error = %v", err)
	}
}

func TestRunLoopReportsTurnMarkerWriteFailure(t *testing.T) {
	t.Parallel()

	out := &eventWriter{enc: json.NewEncoder(errorWriter{})}
	err := runLoop(context.Background(), nil, strings.NewReader("{}\n"), out)
	if err == nil || !strings.Contains(err.Error(), "write turn_done event") {
		t.Fatalf("runLoop() error = %v, want turn marker write failure", err)
	}
	if out.Err() == nil {
		t.Fatal("event writer did not retain its first error")
	}
}

func TestEventWriterKeepsFirstFailure(t *testing.T) {
	t.Parallel()

	out := &eventWriter{enc: json.NewEncoder(errorWriter{})}
	out.Emit(llmagent.Event{Kind: llmagent.EventError, Text: "safe message"})
	first := out.Err()
	if first == nil {
		t.Fatal("Emit did not retain the write failure")
	}
	if err := out.Encode(llmagent.Event{Kind: llmagent.EventTurnDone}); !errors.Is(err, first) {
		t.Fatalf("second Encode error = %v, want original %v", err, first)
	}
}
