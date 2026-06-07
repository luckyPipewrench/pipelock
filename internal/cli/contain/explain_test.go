// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExplain_HappyPathText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-1","class":"tool_ignores_proxy","process":"node","pid":123,"uid":987,"dest":"203.0.113.10","port":443,"protocol":"tcp"}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "text"}, "evt-1")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"event: evt-1",
		"class: tool_ignores_proxy",
		"process: node pid=123",
		"uid: 987",
		"destination: 203.0.113.10:443",
		"tool ignores proxy settings",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunExplain_JSONIncludesDefaultRemediation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-2","class":"direct_dns_blocked","dest":"198.51.100.53","port":53}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "json"}, "evt-2")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, `"remediation": "direct DNS is blocked`) {
		t.Fatalf("json output missing remediation:\n%s", got)
	}
}

func TestRunExplain_PrintsExplicitZeroMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	line := `{"id":"evt-root","class":"not_routing_through_pipelock","process":"init","pid":0,"uid":0,"dest":"127.0.0.1","port":0}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write events: %v", err)
	}

	var out bytes.Buffer
	err := runExplain(&out, containExplainOpts{eventsPath: path, format: "text"}, "evt-root")
	if err != nil {
		t.Fatalf("runExplain: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"process: init pid=0",
		"uid: 0",
		"destination: 127.0.0.1:0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}
