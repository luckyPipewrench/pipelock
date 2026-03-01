package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateMcporter_BasicWrap(t *testing.T) {
	input := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {"HOME": "/home/user"}
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse output: %v\nraw: %s", err, buf.String())
	}

	servers := result["mcpServers"].(map[string]interface{})
	fs := servers["filesystem"].(map[string]interface{})

	if fs["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatalf("command should be pipelock, got %v", fs["command"])
	}

	args := fs["args"].([]interface{})
	// Should contain: mcp, proxy, --config, pipelock.yaml, --env, HOME, --, npx, -y, ...
	foundSep := false
	foundEnv := false
	for i, a := range args {
		if a == "--" {
			foundSep = true
		}
		if a == "--env" && i+1 < len(args) && args[i+1] == "HOME" { //nolint:goconst // test value
			foundEnv = true
		}
	}
	if !foundSep {
		t.Fatal("expected -- separator in args")
	}
	if !foundEnv {
		t.Fatal("expected --env HOME in args")
	}
}

func TestGenerateMcporter_AlreadyWrapped(t *testing.T) {
	input := `{
		"mcpServers": {
			"filesystem": {
				"command": "pipelock",
				"args": ["mcp", "proxy", "--", "npx", "server"]
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse output: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	fs := servers["filesystem"].(map[string]interface{})
	if fs["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("already-wrapped server should remain unchanged")
	}
	// Verify args are unchanged (not double-wrapped).
	args := fs["args"].([]interface{})
	if len(args) != 5 || args[0] != "mcp" || args[1] != "proxy" { //nolint:goconst // test value
		t.Fatalf("args should be unchanged, got %v", args)
	}
}

func TestGenerateMcporter_HTTPUpstream(t *testing.T) {
	input := `{
		"mcpServers": {
			"remote": {
				"url": "http://localhost:8080/mcp"
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse output: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	remote := servers["remote"].(map[string]interface{})
	if remote["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("expected pipelock wrapper")
	}
	args := remote["args"].([]interface{})
	hasUpstream := false
	for i, a := range args {
		if a == "--upstream" && i+1 < len(args) && args[i+1] == "http://localhost:8080/mcp" { //nolint:goconst // test value
			hasUpstream = true
		}
	}
	if !hasUpstream {
		t.Fatal("expected --upstream in args for HTTP server")
	}
}

func TestGenerateMcporter_WSUpstream(t *testing.T) {
	input := `{
		"mcpServers": {
			"ws-server": {
				"url": "ws://localhost:9000/mcp"
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse output: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	ws := servers["ws-server"].(map[string]interface{})
	if ws["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("expected pipelock wrapper")
	}
	args := ws["args"].([]interface{})
	hasUpstream := false
	for i, a := range args {
		if a == "--upstream" && i+1 < len(args) && args[i+1] == "ws://localhost:9000/mcp" {
			hasUpstream = true
		}
	}
	if !hasUpstream {
		t.Fatal("expected --upstream ws:// in args")
	}
}

func TestGenerateMcporter_Idempotent(t *testing.T) {
	input := `{
		"mcpServers": {
			"test": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	// First run.
	var buf1 bytes.Buffer
	cmd1 := rootCmd()
	cmd1.SetOut(&buf1)
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd1.Execute(); err != nil {
		t.Fatal(err)
	}

	// Write first output to a temp file.
	tmpFile2 := filepath.Join(t.TempDir(), "mcporter2.json")
	if err := os.WriteFile(tmpFile2, buf1.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// Second run on the output.
	var buf2 bytes.Buffer
	cmd2 := rootCmd()
	cmd2.SetOut(&buf2)
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"generate", "mcporter", "-i", tmpFile2})
	if err := cmd2.Execute(); err != nil {
		t.Fatal(err)
	}

	if buf1.String() != buf2.String() {
		t.Fatalf("not idempotent:\nfirst:  %s\nsecond: %s", buf1.String(), buf2.String())
	}
}

func TestGenerateMcporter_InvalidJSON(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGenerateMcporter_UnknownFormat(t *testing.T) {
	input := `{"unknown_key": true}`

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestGenerateMcporter_InPlace(t *testing.T) {
	input := `{"mcpServers":{"test":{"command":"node","args":["server.js"]}}}` //nolint:goconst

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile, "--in-place"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(tmpFile) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse in-place output: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	test := servers["test"].(map[string]interface{})
	if test["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("in-place write should have wrapped the server")
	}
}

func TestGenerateMcporter_InPlaceWithBackup(t *testing.T) {
	input := `{"mcpServers":{"test":{"command":"node","args":["server.js"]}}}` //nolint:goconst

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile, "--in-place", "--backup"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// .bak should exist with original content.
	bakData, err := os.ReadFile(tmpFile + ".bak") //nolint:gosec // test file
	if err != nil {
		t.Fatalf("backup file not found: %v", err)
	}
	if string(bakData) != input {
		t.Fatal("backup should contain original content")
	}
}

func TestGenerateMcporter_CustomBinAndConfig(t *testing.T) {
	input := `{"mcpServers":{"test":{"command":"node","args":["server.js"]}}}` //nolint:goconst

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{
		"generate", "mcporter", "-i", tmpFile,
		"--pipelock-bin", "/usr/local/bin/pipelock",
		"--config", "/etc/pipelock/strict.yaml",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	test := servers["test"].(map[string]interface{})
	if test["command"] != "/usr/local/bin/pipelock" {
		t.Fatalf("expected custom binary path, got %v", test["command"])
	}

	args := test["args"].([]interface{})
	foundConfig := false
	for i, a := range args {
		if a == "--config" && i+1 < len(args) && args[i+1] == "/etc/pipelock/strict.yaml" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Fatal("expected custom config path in args")
	}
}

func TestGenerateMcporter_MultipleServers(t *testing.T) {
	input := `{
		"mcpServers": {
			"stdio-server": {
				"command": "node",
				"args": ["server.js"]
			},
			"http-server": {
				"url": "http://localhost:3000/mcp"
			},
			"wrapped": {
				"command": "pipelock",
				"args": ["mcp", "proxy", "--", "python", "server.py"]
			}
		}
	}`

	var buf, stderr bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&stderr)

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})

	// stdio-server should be wrapped.
	stdio := servers["stdio-server"].(map[string]interface{})
	if stdio["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("stdio-server should be wrapped")
	}

	// http-server should be wrapped with --upstream.
	http := servers["http-server"].(map[string]interface{})
	if http["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("http-server should be wrapped")
	}

	// wrapped should remain unchanged.
	w := servers["wrapped"].(map[string]interface{})
	if w["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("wrapped should remain pipelock")
	}
	wArgs := w["args"].([]interface{})
	if len(wArgs) != 5 {
		t.Fatalf("wrapped args should be unchanged (5 items), got %d", len(wArgs))
	}
}

func TestGenerateMcporter_PreservesExtraKeys(t *testing.T) {
	input := `{
		"globalShortcut": "ctrl+space",
		"mcpServers": {
			"test": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "mcporter.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if result["globalShortcut"] != "ctrl+space" {
		t.Fatal("extra keys should be preserved")
	}
}

func TestGenerateMcporter_FileNotFound(t *testing.T) {
	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"generate", "mcporter", "-i", "/nonexistent/mcporter.json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestGenerateMcporter_URLEntryPreservesEnv(t *testing.T) {
	input := `{
		"mcpServers": {
			"gateway": {
				"url": "ws://localhost:3000/mcp",
				"env": {"GATEWAY_TOKEN": "secret", "GATEWAY_URL": "ws://localhost:3000"}
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	gw := servers["gateway"].(map[string]interface{})

	// env block must be preserved.
	envBlock, ok := gw["env"].(map[string]interface{})
	if !ok {
		t.Fatal("env block should be preserved for URL-based entries")
	}
	if envBlock["GATEWAY_TOKEN"] != "secret" {
		t.Fatal("GATEWAY_TOKEN should be preserved")
	}

	// --env flags should be generated in args.
	args := gw["args"].([]interface{})
	envCount := 0
	for _, a := range args {
		if a == "--env" {
			envCount++
		}
	}
	if envCount != 2 {
		t.Errorf("expected 2 --env flags for URL entry, got %d", envCount)
	}
}

func TestGenerateMcporter_FlagLikeEnvKeysDropped(t *testing.T) {
	// Env keys starting with "-" could inject pipelock flags via --env.
	// They must be silently dropped from the generated args.
	input := `{
		"mcpServers": {
			"test": {
				"command": "node",
				"args": ["server.js"],
				"env": {"--config": "/dev/null", "SAFE_VAR": "ok", "-x": "bad"}
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	test := servers["test"].(map[string]interface{})
	args := test["args"].([]interface{})

	// Only SAFE_VAR should appear after --env; flag-like keys must be dropped.
	envCount := 0
	for i, a := range args {
		if a == "--env" {
			envCount++
			if i+1 < len(args) {
				val := args[i+1].(string)
				if val != "SAFE_VAR" {
					t.Errorf("flag-like env key %q was not dropped", val)
				}
			}
		}
	}
	if envCount != 1 {
		t.Errorf("expected 1 --env flag (SAFE_VAR only), got %d", envCount)
	}
}

func TestGenerateMcporter_NonStringURLRejectsEntry(t *testing.T) {
	input := `{
		"mcpServers": {
			"broken": {
				"url": 12345
			}
		}
	}`

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-string url")
	}
}

func TestGenerateMcporter_NonStringCommandRejectsEntry(t *testing.T) {
	input := `{
		"mcpServers": {
			"broken": {
				"command": ["not", "a", "string"]
			}
		}
	}`

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for non-string command")
	}
}

func TestGenerateMcporter_OutputFile(t *testing.T) {
	input := `{"mcpServers":{"test":{"command":"node","args":["server.js"]}}}` //nolint:goconst

	tmpDir := t.TempDir()
	inFile := filepath.Join(tmpDir, "in.json")
	outFile := filepath.Join(tmpDir, "out.json")
	if err := os.WriteFile(inFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"generate", "mcporter", "-i", inFile, "-o", outFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(outFile) //nolint:gosec // test file
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse: %v", err)
	}
	servers := result["mcpServers"].(map[string]interface{})
	test := servers["test"].(map[string]interface{})
	if test["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("output file should contain wrapped server")
	}
}

func TestGenerateMcporter_NoCommandNoURL(t *testing.T) {
	// Entry with neither command nor url should pass through unchanged.
	input := `{
		"mcpServers": {
			"custom": {
				"type": "sse",
				"endpoint": "http://example.com"
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	custom := servers["custom"].(map[string]interface{})
	if custom["type"] != "sse" {
		t.Fatal("passthrough entry should be unchanged")
	}
}

func TestGenerateMcporter_InvalidServerEntry(t *testing.T) {
	input := `{
		"mcpServers": {
			"broken": "not an object"
		}
	}`

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid server entry")
	}
}

func TestGenerateMcporter_McpServersNotObject(t *testing.T) {
	input := `{"mcpServers": "not-an-object"}`

	cmd := rootCmd()
	cmd.SetErr(&bytes.Buffer{})
	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when mcpServers is not an object")
	}
}

func TestGenerateMcporter_OutputFileError(t *testing.T) {
	input := `{"mcpServers":{"test":{"command":"node","args":["server.js"]}}}` //nolint:goconst

	tmpFile := filepath.Join(t.TempDir(), "in.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	// Write to a nonexistent directory.
	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile, "-o", "/nonexistent/dir/out.json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error writing to nonexistent dir")
	}
}

func TestGenerateMcporter_URLEntryAlreadyWrapped(t *testing.T) {
	// URL entry that also has command/args indicating pipelock wrapping.
	input := `{
		"mcpServers": {
			"gateway": {
				"url": "ws://localhost:3000/mcp",
				"command": "pipelock",
				"args": ["mcp", "proxy", "--upstream", "ws://localhost:3000/mcp"]
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	gw := servers["gateway"].(map[string]interface{})
	// Should be skipped (already wrapped).
	if gw["command"] != "pipelock" { //nolint:goconst // test value
		t.Fatal("already-wrapped URL entry should remain unchanged")
	}
}

func TestGenerateMcporter_IsAlreadyWrapped_DashDashBeforeProxy(t *testing.T) {
	// Args with -- before "proxy" should not be considered wrapped.
	if isAlreadyWrapped("pipelock", []string{"mcp", "--", "proxy"}) {
		t.Fatal("should not detect as wrapped when -- appears before proxy")
	}
}

func TestGenerateMcporter_ToStringSlice_NonStringElements(t *testing.T) {
	result := toStringSlice([]interface{}{"hello", 123, true, "world"})
	if len(result) != 2 || result[0] != "hello" || result[1] != "world" {
		t.Fatalf("expected [hello world], got %v", result)
	}
}

func TestGenerateMcporter_AtomicWriteFile_StatFailure(t *testing.T) {
	err := atomicWriteFile("/nonexistent/path/file.json", []byte("{}"), false)
	if err == nil {
		t.Fatal("expected error for stat on nonexistent path")
	}
}

func TestGenerateMcporter_UpstreamFlagLikeEnvKeysDropped(t *testing.T) {
	// Flag-like env keys should be dropped in upstream entries too.
	input := `{
		"mcpServers": {
			"remote": {
				"url": "http://localhost:8080/mcp",
				"env": {"--evil": "bad", "SAFE": "ok"}
			}
		}
	}`

	var buf bytes.Buffer
	cmd := rootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})

	tmpFile := filepath.Join(t.TempDir(), "test.json")
	if err := os.WriteFile(tmpFile, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"generate", "mcporter", "-i", tmpFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("parse: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	remote := servers["remote"].(map[string]interface{})
	args := remote["args"].([]interface{})
	envCount := 0
	for _, a := range args {
		if a == "--env" {
			envCount++
		}
	}
	if envCount != 1 {
		t.Errorf("expected 1 --env flag (SAFE only), got %d", envCount)
	}
}
