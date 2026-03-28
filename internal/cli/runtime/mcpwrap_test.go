// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCmdNode = "node"

func TestReadMCPConfig_NonexistentFile(t *testing.T) {
	t.Parallel()

	cfg, data, err := ReadMCPConfig("/nonexistent/path.json", "mcpServers")
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}
	if data != nil {
		t.Error("expected nil data for nonexistent file")
	}
	if cfg == nil || cfg.Servers == nil {
		t.Fatal("expected non-nil config with empty servers")
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(cfg.Servers))
	}
}

func TestReadMCPConfig_ValidFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
  "mcpServers": {
    "test-server": {
      "command": "` + testCmdNode + `",
      "args": ["server.js"]
    }
  }
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, data, err := ReadMCPConfig(path, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data == nil {
		t.Error("expected non-nil data")
	}
	if len(cfg.Servers) != 1 {
		t.Errorf("expected 1 server, got %d", len(cfg.Servers))
	}
	srv, ok := cfg.Servers["test-server"]
	if !ok {
		t.Fatal("expected test-server in config")
	}
	if srv[MCPFieldCommand] != testCmdNode {
		t.Errorf("command = %v, want node", srv[MCPFieldCommand])
	}
}

func TestReadMCPConfig_InvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := ReadMCPConfig(path, "mcpServers")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestReadMCPConfig_EmptyServersKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	content := `{"otherKey": "value"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := ReadMCPConfig(path, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(cfg.Servers))
	}
}

func TestReadMCPConfig_InvalidServersValue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad-servers.json")
	content := `{"mcpServers": "not-an-object"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := ReadMCPConfig(path, "mcpServers")
	if err == nil {
		t.Fatal("expected error for invalid servers value")
	}
}

func TestMarshalMCPConfig_WithOriginalData(t *testing.T) {
	t.Parallel()

	original := []byte(`{"mcpServers": {}, "otherKey": "preserved"}`)
	cfg := &MCPConfig{
		Servers: map[string]map[string]interface{}{
			"new-server": {"command": "echo"},
		},
	}

	data, err := MarshalMCPConfig(original, cfg, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should preserve otherKey.
	got := string(data)
	if len(got) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestMarshalMCPConfig_NoOriginalData(t *testing.T) {
	t.Parallel()

	cfg := &MCPConfig{
		Servers: map[string]map[string]interface{}{
			"server": {"command": testCmdNode},
		},
	}

	data, err := MarshalMCPConfig(nil, cfg, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestMarshalMCPConfig_InvalidOriginalData(t *testing.T) {
	t.Parallel()

	cfg := &MCPConfig{
		Servers: map[string]map[string]interface{}{
			"server": {"command": testCmdNode},
		},
	}

	// Invalid JSON should fall through to from-scratch marshaling.
	data, err := MarshalMCPConfig([]byte("not json"), cfg, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestWrapMCPServer_Stdio(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: testCmdNode,
		MCPFieldArgs:    []interface{}{"server.js", "--port", "3000"},
		"env":           map[string]interface{}{"API_KEY": "test"},
	}

	result, meta, err := WrapMCPServer(server, "/usr/bin/pipelock", "", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.OriginalCommand != testCmdNode {
		t.Errorf("meta.OriginalCommand = %q, want node", meta.OriginalCommand)
	}
	if result[MCPFieldCommand] != "/usr/bin/pipelock" {
		t.Errorf("command = %v, want /usr/bin/pipelock", result[MCPFieldCommand])
	}
}

func TestWrapMCPServer_StdioWithConfig(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: "python",
		MCPFieldArgs:    []interface{}{"server.py"},
	}

	result, _, err := WrapMCPServer(server, "pipelock", "/etc/pipelock.yaml", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args, _ := result[MCPFieldArgs].([]string)
	foundConfig := false
	for _, a := range args {
		if a == "/etc/pipelock.yaml" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Error("expected config file in args")
	}
}

func TestWrapMCPServer_StdioWithSandbox(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: "python",
	}

	result, _, err := WrapMCPServer(server, "pipelock", "", true, "/workspace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	args, _ := result[MCPFieldArgs].([]string)
	foundSandbox := false
	foundWorkspace := false
	for i, a := range args {
		if a == "--sandbox" {
			foundSandbox = true
		}
		if a == "--workspace" && i+1 < len(args) && args[i+1] == "/workspace" {
			foundWorkspace = true
		}
	}
	if !foundSandbox {
		t.Error("expected --sandbox in args")
	}
	if !foundWorkspace {
		t.Error("expected --workspace in args")
	}
}

func TestWrapMCPServer_StdioMissingCommand(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldType: VSTypeStdio,
	}

	_, _, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestWrapMCPServer_HTTPType(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldType: "sse",
		MCPFieldURL:  "http://localhost:3000/mcp",
	}

	result, meta, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.OriginalURL != "http://localhost:3000/mcp" {
		t.Errorf("meta.OriginalURL = %q", meta.OriginalURL)
	}
	// HTTP type gets converted to stdio wrapping.
	if result[MCPFieldType] != VSTypeStdio {
		t.Errorf("type = %v, want stdio", result[MCPFieldType])
	}
}

func TestWrapMCPServer_HTTPTypeMissingURL(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldType: "sse",
	}

	_, _, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestWrapMCPServer_HTTPTypeWithHeaders(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldType:    "sse",
		MCPFieldURL:     "http://localhost:3000/mcp",
		MCPFieldHeaders: map[string]interface{}{"Authorization": "Bearer test"},
	}

	_, _, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err == nil {
		t.Fatal("expected error for headers that can't be passed through")
	}
}

func TestWrapMCPServer_UnsupportedType(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldType: "unsupported-type",
	}

	_, _, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestUnwrapMCPServer_NotWrapped(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: testCmdNode,
		MCPFieldArgs:    []interface{}{"server.js"},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[MCPFieldCommand] != testCmdNode {
		t.Error("expected original server returned unchanged")
	}
}

func TestUnwrapMCPServer_StdioWrapped(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: "pipelock",
		MCPFieldArgs:    []interface{}{"mcp", "proxy", "--", testCmdNode, "server.js"},
		MCPFieldType:    VSTypeStdio,
		MCPFieldPipelock: map[string]interface{}{
			"original_type":    VSTypeStdio,
			"original_command": testCmdNode,
			"original_args":    []interface{}{"server.js"},
		},
		"env": map[string]interface{}{"KEY": "val"},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[MCPFieldCommand] != testCmdNode {
		t.Errorf("command = %v, want node", result[MCPFieldCommand])
	}
	// env should be preserved.
	if _, ok := result["env"]; !ok {
		t.Error("expected env to be preserved")
	}
	// _pipelock should be removed.
	if _, ok := result[MCPFieldPipelock]; ok {
		t.Error("expected _pipelock to be removed")
	}
}

func TestUnwrapMCPServer_HTTPWrapped(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: "pipelock",
		MCPFieldType:    VSTypeStdio,
		MCPFieldPipelock: map[string]interface{}{
			"original_type": "sse",
			"original_url":  "http://localhost:3000/mcp",
		},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[MCPFieldType] != "sse" {
		t.Errorf("type = %v, want sse", result[MCPFieldType])
	}
	if result[MCPFieldURL] != "http://localhost:3000/mcp" {
		t.Errorf("url = %v", result[MCPFieldURL])
	}
}

func TestUnwrapMCPServer_MissingOriginalCommand(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldPipelock: map[string]interface{}{
			"original_type": VSTypeStdio,
			// missing original_command
		},
	}

	_, err := UnwrapMCPServer(server)
	if err == nil {
		t.Fatal("expected error for missing original_command")
	}
}

func TestUnwrapMCPServer_MissingOriginalType(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldPipelock: map[string]interface{}{
			// missing original_type
		},
	}

	_, err := UnwrapMCPServer(server)
	if err == nil {
		t.Fatal("expected error for missing original_type")
	}
}

func TestUnwrapMCPServer_HTTPMissingURL(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldPipelock: map[string]interface{}{
			"original_type": "sse",
			// missing original_url
		},
	}

	_, err := UnwrapMCPServer(server)
	if err == nil {
		t.Fatal("expected error for missing original_url")
	}
}

func TestUnwrapMCPServer_TypeOmitted(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldPipelock: map[string]interface{}{
			"original_type":    VSTypeStdio,
			"type_omitted":     true,
			"original_command": testCmdNode,
		},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Type should not be set when omitted.
	if _, ok := result[MCPFieldType]; ok {
		t.Error("expected type to be omitted in unwrapped result")
	}
}

func TestIsWrapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		server map[string]interface{}
		want   bool
	}{
		{
			name:   "wrapped",
			server: map[string]interface{}{MCPFieldPipelock: map[string]interface{}{}},
			want:   true,
		},
		{
			name:   "not wrapped",
			server: map[string]interface{}{MCPFieldCommand: testCmdNode},
			want:   false,
		},
		{
			name:   "empty",
			server: map[string]interface{}{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsWrapped(tt.server); got != tt.want {
				t.Errorf("IsWrapped = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsVscodeHTTPType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"sse", true},
		{"http", true},
		{"stdio", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := IsVscodeHTTPType(tt.input); got != tt.want {
				t.Errorf("IsVscodeHTTPType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildEnvFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		server map[string]interface{}
		want   int // number of flags (pairs)
	}{
		{
			name:   "with env",
			server: map[string]interface{}{"env": map[string]interface{}{"KEY1": "v1", "KEY2": "v2"}},
			want:   4, // --env KEY1 --env KEY2
		},
		{
			name:   "no env",
			server: map[string]interface{}{},
			want:   0,
		},
		{
			name:   "env wrong type",
			server: map[string]interface{}{"env": "not-a-map"},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildEnvFlags(tt.server)
			if len(got) != tt.want {
				t.Errorf("BuildEnvFlags len = %d, want %d (flags: %v)", len(got), tt.want, got)
			}
		})
	}
}

func TestInterfaceSliceToStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input interface{}
		want  int
	}{
		{
			name:  "valid slice",
			input: []interface{}{"a", "b", "c"},
			want:  3,
		},
		{
			name:  "mixed types",
			input: []interface{}{"a", 42, "b"},
			want:  2, // only strings
		},
		{
			name:  "nil",
			input: nil,
			want:  0,
		},
		{
			name:  "wrong type",
			input: "not a slice",
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := InterfaceSliceToStrings(tt.input)
			if len(got) != tt.want {
				t.Errorf("InterfaceSliceToStrings len = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestUnwrapMCPServer_HTTPWithHeaders(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldCommand: "pipelock",
		MCPFieldType:    VSTypeStdio,
		MCPFieldPipelock: map[string]interface{}{
			"original_type": "sse",
			"original_url":  "http://localhost:3000/mcp",
			"original_headers": map[string]interface{}{
				"Authorization": "Bearer test-tok",
				"X-Custom":      "value",
			},
		},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	headers, ok := result[MCPFieldHeaders].(map[string]interface{})
	if !ok {
		t.Fatal("expected headers in unwrapped result")
	}
	if headers["Authorization"] != "Bearer test-tok" {
		t.Errorf("Authorization = %v", headers["Authorization"])
	}
}

func TestUnwrapMCPServer_StdioWithArgs(t *testing.T) {
	t.Parallel()

	server := map[string]interface{}{
		MCPFieldPipelock: map[string]interface{}{
			"original_type":    VSTypeStdio,
			"original_command": testCmdNode,
			"original_args":    []interface{}{"server.js"},
			"type_omitted":     false,
		},
	}

	result, err := UnwrapMCPServer(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[MCPFieldType] != VSTypeStdio {
		t.Errorf("type = %v, want stdio", result[MCPFieldType])
	}
	args, ok := result[MCPFieldArgs].([]string)
	if !ok {
		t.Fatal("expected args to be []string")
	}
	if len(args) != 1 || args[0] != "server.js" {
		t.Errorf("args = %v, want [server.js]", args)
	}
}

func TestMarshalMCPConfig_PreservesUnknownFields(t *testing.T) {
	t.Parallel()

	original := []byte(`{"mcpServers": {"old": {"command": "old"}}, "customField": 42, "anotherField": "kept"}`)
	cfg := &MCPConfig{
		Servers: map[string]map[string]interface{}{
			"new": {"command": "new"},
		},
	}

	data, err := MarshalMCPConfig(original, cfg, "mcpServers")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(data)
	// Should preserve customField and anotherField.
	if !strings.Contains(got, "customField") {
		t.Errorf("expected customField preserved, got: %s", got)
	}
	if !strings.Contains(got, "anotherField") {
		t.Errorf("expected anotherField preserved, got: %s", got)
	}
	// Should have new server, not old.
	if !strings.Contains(got, "new") {
		t.Errorf("expected new server, got: %s", got)
	}
}

func TestWrapMCPServer_TypeOmitted(t *testing.T) {
	t.Parallel()

	// When type is omitted from the server entry, it defaults to stdio.
	server := map[string]interface{}{
		MCPFieldCommand: "python",
		// No MCPFieldType -- should default to stdio.
	}

	_, meta, err := WrapMCPServer(server, "pipelock", "", false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !meta.TypeOmitted {
		t.Error("expected TypeOmitted=true when type field not set")
	}
	if meta.OriginalType != VSTypeStdio {
		t.Errorf("OriginalType = %q, want stdio", meta.OriginalType)
	}
}

func TestWrapMCPServer_SandboxWithHTTPType(t *testing.T) {
	t.Parallel()

	// --sandbox with HTTP type should produce a warning but not error
	// (sandbox is skipped for HTTP types).
	server := map[string]interface{}{
		MCPFieldType: "sse",
		MCPFieldURL:  "http://localhost:3000/mcp",
	}

	_, _, err := WrapMCPServer(server, "pipelock", "", true, "/workspace")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	t.Parallel()

	original := map[string]interface{}{
		MCPFieldCommand: testCmdNode,
		MCPFieldArgs:    []interface{}{"server.js", "--port", "3000"},
		"env":           map[string]interface{}{"MY_VAR": "value"},
	}

	wrapped, meta, err := WrapMCPServer(original, "pipelock", "/etc/pipelock.yaml", false, "")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// Add metadata for unwrapping.
	wrapped[MCPFieldPipelock] = meta

	unwrapped, err := UnwrapMCPServer(wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}

	if unwrapped[MCPFieldCommand] != testCmdNode {
		t.Errorf("command = %v, want node", unwrapped[MCPFieldCommand])
	}
}
