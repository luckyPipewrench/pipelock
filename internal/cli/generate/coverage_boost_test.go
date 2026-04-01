// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// ---------- generateConfigCmd error paths ----------

func TestGenerateConfigCmd_UnknownPreset(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "nonexistent"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for unknown preset")
	}
}

func TestGenerateConfigCmd_StrictPreset(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "strict"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify valid YAML output.
	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid YAML output: %v", err)
	}
}

func TestGenerateConfigCmd_AuditPreset(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "audit"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid YAML output: %v", err)
	}
}

func TestGenerateConfigCmd_BalancedPreset(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "balanced"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(buf.String()), &parsed); err != nil {
		t.Fatalf("invalid YAML output: %v", err)
	}
}

func TestGenerateConfigCmd_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "pipelock.yaml")

	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--preset", "strict", "--output", outPath})
	cmd.SetErr(&strings.Builder{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("output file is empty")
	}
	if !strings.Contains(string(data), "strict") {
		t.Error("output should mention strict preset")
	}
}

func TestGenerateConfigCmd_OutputFile_BadPath(t *testing.T) {
	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "config", "--output", "/nonexistent/dir/pipelock.yaml"})
	cmd.SetErr(&strings.Builder{})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for bad output path")
	}
}

// ---------- strictPreset / auditPreset ----------

func TestStrictPreset_Values(t *testing.T) {
	cfg := strictPreset()
	if cfg.Mode != "strict" {
		t.Errorf("Mode = %q, want strict", cfg.Mode)
	}
	if cfg.FetchProxy.Monitoring.EntropyThreshold != 3.5 {
		t.Errorf("EntropyThreshold = %v, want 3.5", cfg.FetchProxy.Monitoring.EntropyThreshold)
	}
	if cfg.FetchProxy.Monitoring.MaxURLLength != 500 {
		t.Errorf("MaxURLLength = %d, want 500", cfg.FetchProxy.Monitoring.MaxURLLength)
	}
	if cfg.FetchProxy.Monitoring.MaxReqPerMinute != 30 {
		t.Errorf("MaxReqPerMinute = %d, want 30", cfg.FetchProxy.Monitoring.MaxReqPerMinute)
	}
	if cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold != 3.5 {
		t.Errorf("SubdomainEntropyThreshold = %v, want 3.5", cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold)
	}
}

func TestAuditPreset_Values(t *testing.T) {
	cfg := auditPreset()
	if cfg.Mode != "audit" {
		t.Errorf("Mode = %q, want audit", cfg.Mode)
	}
	if cfg.Enforce == nil || *cfg.Enforce {
		t.Error("Enforce should be false in audit mode")
	}
	if !cfg.Logging.IncludeAllowed {
		t.Error("IncludeAllowed should be true in audit mode")
	}
	if !cfg.Logging.IncludeBlocked {
		t.Error("IncludeBlocked should be true in audit mode")
	}
}

// ---------- mcporter helper functions ----------

func TestIsAlreadyWrapped(t *testing.T) {
	cases := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{
			name:    "wrapped stdio",
			command: "pipelock",
			args:    []string{"mcp", "proxy", "--config", "p.yaml", "--", "node", "server.js"},
			want:    true,
		},
		{
			name:    "wrapped with path",
			command: "/usr/bin/pipelock",
			args:    []string{"mcp", "proxy", "--upstream", "http://example.com"},
			want:    true,
		},
		{
			name:    "not wrapped",
			command: "node",
			args:    []string{"server.js"},
			want:    false,
		},
		{
			name:    "empty args",
			command: "pipelock",
			args:    nil,
			want:    false,
		},
		{
			name:    "mcp without proxy",
			command: "pipelock",
			args:    []string{"mcp", "scan"},
			want:    false,
		},
		{
			name:    "proxy before separator but not mcp",
			command: "pipelock",
			args:    []string{"proxy", "mcp"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isAlreadyWrapped(tc.command, tc.args)
			if got != tc.want {
				t.Errorf("isAlreadyWrapped(%q, %v) = %v, want %v", tc.command, tc.args, got, tc.want)
			}
		})
	}
}

func TestToStringSlice(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result, err := toStringSlice(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid strings", func(t *testing.T) {
		result, err := toStringSlice([]interface{}{"a", "b", "c"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
			t.Errorf("unexpected result: %v", result)
		}
	})

	t.Run("non-string element", func(t *testing.T) {
		_, err := toStringSlice([]interface{}{"a", 42})
		if err == nil {
			t.Error("expected error for non-string element")
		}
	})
}

func TestCopyExtraFields(t *testing.T) {
	dst := map[string]interface{}{
		"command": "pipelock",
		"args":    []string{"mcp"},
	}
	src := map[string]interface{}{
		"command":     "node",
		"args":        []string{"server.js"},
		"metadata":    "preserved",
		"alwaysAllow": []string{"tool"},
	}

	copyExtraFields(dst, src, "command", "args")

	if dst["metadata"] != "preserved" {
		t.Error("metadata should be copied")
	}
	if dst["command"] != "pipelock" {
		t.Error("command should not be overwritten (managed field)")
	}
}

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	original := []byte(`{"original": true}`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("basic write", func(t *testing.T) {
		newData := []byte(`{"updated": true}`)
		if err := atomicWriteFile(path, newData, false); err != nil {
			t.Fatalf("atomicWriteFile: %v", err)
		}

		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("reading: %v", err)
		}
		if string(data) != string(newData) {
			t.Errorf("content mismatch: got %q", string(data))
		}
	})

	t.Run("with backup", func(t *testing.T) {
		newData := []byte(`{"v3": true}`)
		if err := atomicWriteFile(path, newData, true); err != nil {
			t.Fatalf("atomicWriteFile with backup: %v", err)
		}

		bakPath := path + ".bak"
		if _, err := os.Stat(bakPath); err != nil {
			t.Error("expected .bak file to exist")
		}
	})

	t.Run("nonexistent source", func(t *testing.T) {
		err := atomicWriteFile("/nonexistent/file.json", []byte("data"), false)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

// ---------- mcporter URL-based server ----------

func TestWrapServerEntry_URLBased(t *testing.T) {
	raw := json.RawMessage(`{"url": "http://localhost:8090/sse"}`)

	entry, err := wrapServerEntry(raw, "pipelock", "pipelock.yaml")
	if err != nil {
		t.Fatalf("wrapServerEntry: %v", err)
	}
	if entry.skipped {
		t.Error("should not be skipped")
	}

	m := entry.value.(map[string]interface{})
	if m["command"] != mcporterBinaryName {
		t.Errorf("command = %v, want pipelock", m["command"])
	}
	args := m["args"].([]string)
	foundUpstream := false
	for _, a := range args {
		if a == flagUpstream {
			foundUpstream = true
		}
	}
	if !foundUpstream {
		t.Error("expected --upstream flag for URL-based server")
	}
}

func TestWrapServerEntry_NoCommandNoURL(t *testing.T) {
	raw := json.RawMessage(`{"metadata": "just metadata"}`)

	entry, err := wrapServerEntry(raw, "pipelock", "pipelock.yaml")
	if err != nil {
		t.Fatalf("wrapServerEntry: %v", err)
	}
	// Should pass through unchanged.
	m := entry.value.(map[string]interface{})
	if _, ok := m["command"]; ok {
		t.Error("should not add command field")
	}
}

func TestWrapServerEntry_BadJSON(t *testing.T) {
	raw := json.RawMessage(`not json`)
	_, err := wrapServerEntry(raw, "pipelock", "pipelock.yaml")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestWrapServerEntry_CommandNotString(t *testing.T) {
	raw := json.RawMessage(`{"command": 42}`)
	_, err := wrapServerEntry(raw, "pipelock", "pipelock.yaml")
	if err == nil {
		t.Error("expected error when command is not a string")
	}
}

func TestWrapServerEntry_URLNotString(t *testing.T) {
	raw := json.RawMessage(`{"url": 42}`)
	_, err := wrapServerEntry(raw, "pipelock", "pipelock.yaml")
	if err == nil {
		t.Error("expected error when url is not a string")
	}
}

// ---------- mcporter env key sanitization ----------

func TestWrapStdioEntry_SkipsDashPrefixedEnvKeys(t *testing.T) {
	envMap := map[string]interface{}{
		"VALID_KEY": "value",
		"--config":  "injected",
		"":          "empty",
	}

	result := wrapStdioEntry("node", []string{"server.js"}, envMap, "pipelock", "pipelock.yaml")

	args := result["args"].([]string)
	for i, a := range args {
		if a == flagEnv && i+1 < len(args) {
			if args[i+1] == "--config" || args[i+1] == "" {
				t.Errorf("should not pass through dash-prefixed or empty env key: %q", args[i+1])
			}
		}
	}
}

// ---------- mcporter --in-place and --output mutually exclusive ----------

func TestGenerateMcporterCmd_InPlaceAndOutputConflict(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(tmpFile, []byte(testMCPInput), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile, "--in-place", "-o", "out.json"})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --in-place with --output")
	}
}

// ---------- mcporter --in-place ----------

func TestGenerateMcporterCmd_InPlace(t *testing.T) {
	dir := t.TempDir()
	tmpFile := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(tmpFile, []byte(testMCPInput), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile, "--in-place"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(tmpFile))
	if err != nil {
		t.Fatalf("reading modified file: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	servers := result["mcpServers"].(map[string]interface{})
	test := servers["test"].(map[string]interface{})
	if test["command"] != mcporterBinaryName {
		t.Error("in-place modification should wrap the server")
	}
}

func TestGenerateMcporterCmd_NoMcpServersKey(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmpFile, []byte(`{"other": "data"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := testRootCmd()
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing mcpServers key")
	}
}
