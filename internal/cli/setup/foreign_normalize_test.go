// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// foreignBinary is a path that is never this test binary, so classifyWrapper
// treats an entry running it through `mcp proxy` as a foreign wrapper.
const foreignBinary = "/nonexistent/other-pipelock"

func argsOf(t *testing.T, server map[string]interface{}) []string {
	t.Helper()
	return commandArgStrings(server[mcpFieldArgs])
}

func argsContain(args []string, sub string) bool {
	for _, a := range args {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

// childTail returns the arguments after the `--` separator.
func childTail(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return nil
}

// TestNormalizeForeign_VscodeStdioSingleWrap is the upgrade case: installing
// over a wrapper written by a pipelock at a different path must produce a single
// clean wrap through THIS binary, recording the recovered inner command as the
// original, with the foreign binary path and the foreign flags gone and the
// env passthrough preserved.
func TestNormalizeForeign_VscodeStdioSingleWrap(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs: []interface{}{
			"mcp", "proxy", "--config", "/old/pipelock.yaml", "--env", "API_KEY", "--", "node", "server.js",
		},
		"env": map[string]interface{}{"API_KEY": "unused-by-key-extraction"},
	}
	result, meta, _, err := wrapVscodeServer(foreign, self, "/new/pipelock.yaml", t.TempDir(), "srv")
	if err != nil {
		t.Fatalf("wrapVscodeServer: %v", err)
	}
	if result[mcpFieldCommand] != self {
		t.Fatalf("wrapped command = %v, want this binary %q", result[mcpFieldCommand], self)
	}
	if meta.OriginalCommand != "node" || strings.Join(meta.OriginalArgs, ",") != "server.js" {
		t.Fatalf("recovered original from invocation wrong: cmd=%q args=%v", meta.OriginalCommand, meta.OriginalArgs)
	}
	args := argsOf(t, result)
	if tail := childTail(args); len(tail) != 2 || tail[0] != "node" || tail[1] != "server.js" {
		t.Fatalf("child tail = %v, want [node server.js]", tail)
	}
	if argsContain(args, "other-pipelock") {
		t.Fatalf("foreign binary survived (nested wrap): %v", args)
	}
	if argsContain(args, "/old/pipelock.yaml") {
		t.Fatalf("foreign --config survived instead of the current one: %v", args)
	}
	if !argsContain(args, "/new/pipelock.yaml") {
		t.Fatalf("current --config not rebuilt: %v", args)
	}
	if !argsContain(args, "API_KEY") {
		t.Fatalf("env passthrough not preserved: %v", args)
	}
	// The env flag is rebuilt from the env block, not duplicated from the
	// foreign invocation's own --env flags.
	envCount := 0
	for _, a := range args {
		if a == "--env" {
			envCount++
		}
	}
	if envCount != 1 {
		t.Fatalf("--env flag count = %d, want 1 (no duplication)", envCount)
	}
}

func TestNormalizeForeign_VscodeHTTPUpstream(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"},
	}
	result, meta, _, err := wrapVscodeServer(foreign, self, "", t.TempDir(), "srv")
	if err != nil {
		t.Fatalf("wrapVscodeServer: %v", err)
	}
	if meta.OriginalURL != "https://api.vendor.example/mcp" {
		t.Fatalf("recovered upstream = %q", meta.OriginalURL)
	}
	args := argsOf(t, result)
	if !argsContain(args, "--upstream") || !argsContain(args, "https://api.vendor.example/mcp") {
		t.Fatalf("upstream not rebuilt: %v", args)
	}
	if argsContain(args, "other-pipelock") {
		t.Fatalf("foreign binary survived: %v", args)
	}
}

// TestNormalizeForeign_VscodeHTTPHeaderFileRefused proves the one case that must
// refuse rather than guess: an older HTTP wrapper whose credentials live in a
// header sidecar cannot be recovered from the invocation alone.
func TestNormalizeForeign_VscodeHTTPHeaderFileRefused(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--header-file", "/old.headers", "--upstream", "https://api.vendor.example/mcp"},
	}
	_, _, _, err = wrapVscodeServer(foreign, self, "", t.TempDir(), "srv")
	if err == nil {
		t.Fatal("expected a refusal for a header-sidecar wrapper, got nil")
	}
	if !strings.Contains(err.Error(), "header sidecar") || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("refusal error lacks the credential reason or remedy: %v", err)
	}
}

// TestNormalizeForeign_ForgedMetadataIgnored proves normalization reads the child
// from the invocation, never from the _pipelock marker. A config-controlled
// marker claiming a different original must not steer the result.
func TestNormalizeForeign_ForgedMetadataIgnored(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "real-server", "--flag"},
		mcpFieldPipelock: map[string]interface{}{
			"original_command": "forged-server",
			"original_args":    []interface{}{"forged"},
		},
	}
	_, meta, _, err := wrapVscodeServer(foreign, self, "", t.TempDir(), "srv")
	if err != nil {
		t.Fatalf("wrapVscodeServer: %v", err)
	}
	if meta.OriginalCommand != "real-server" {
		t.Fatalf("recovered original = %q, want the invocation's real-server (marker was forged)", meta.OriginalCommand)
	}
}

func TestNormalizeForeign_OpenCodeArray(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	t.Run("stdio", func(t *testing.T) {
		foreign := map[string]interface{}{
			mcpFieldType: opencodeTypeLocal,
			mcpFieldCommand: []interface{}{
				foreignBinary, "mcp", "proxy", "--config", "/old.yaml", "--", "node", "server.js",
			},
		}
		result, meta, _, err := wrapOpenCodeServer(foreign, self, "/new.yaml", t.TempDir(), "srv")
		if err != nil {
			t.Fatalf("wrapOpenCodeServer: %v", err)
		}
		if meta.OriginalCommand != "node" {
			t.Fatalf("recovered inner = %q, want node", meta.OriginalCommand)
		}
		cmd := commandArgStrings(result[mcpFieldCommand])
		if cmd[0] != self {
			t.Fatalf("wrapped command[0] = %q, want this binary", cmd[0])
		}
		if argsContain(cmd, "other-pipelock") {
			t.Fatalf("foreign binary survived: %v", cmd)
		}
		if tail := childTail(cmd); len(tail) != 2 || tail[0] != "node" || tail[1] != "server.js" {
			t.Fatalf("child tail = %v, want [node server.js]", tail)
		}
	})
	t.Run("http", func(t *testing.T) {
		foreign := map[string]interface{}{
			mcpFieldType: opencodeTypeLocal,
			mcpFieldCommand: []interface{}{
				foreignBinary, "mcp", "proxy", "--upstream", "https://api.vendor.example/mcp",
			},
		}
		result, meta, _, err := wrapOpenCodeServer(foreign, self, "", t.TempDir(), "srv")
		if err != nil {
			t.Fatalf("wrapOpenCodeServer: %v", err)
		}
		if meta.OriginalURL != "https://api.vendor.example/mcp" {
			t.Fatalf("recovered upstream = %q", meta.OriginalURL)
		}
		cmd := commandArgStrings(result[mcpFieldCommand])
		if !argsContain(cmd, "--upstream") || argsContain(cmd, "other-pipelock") {
			t.Fatalf("upstream not rebuilt cleanly: %v", cmd)
		}
	})
	t.Run("header sidecar refused", func(t *testing.T) {
		foreign := map[string]interface{}{
			mcpFieldType: opencodeTypeLocal,
			mcpFieldCommand: []interface{}{
				foreignBinary, "mcp", "proxy", "--header-file", "/old.headers", "--upstream", "https://api.vendor.example/mcp",
			},
		}
		_, _, _, err := wrapOpenCodeServer(foreign, self, "", t.TempDir(), "srv")
		if err == nil {
			t.Fatal("expected refusal for opencode header-sidecar wrapper, got nil")
		}
		if !strings.Contains(err.Error(), "header sidecar") {
			t.Fatalf("refusal error lacks the credential reason: %v", err)
		}
	})
}

func TestNormalizeForeign_JetBrains(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--sandbox", "--workspace", "/old/ws", "--", "node"},
	}
	result, meta, err := wrapMCPServer(foreign, self, "/new.yaml", true, "/new/ws")
	if err != nil {
		t.Fatalf("wrapMCPServer: %v", err)
	}
	if meta.OriginalCommand != "node" {
		t.Fatalf("recovered inner = %q, want node", meta.OriginalCommand)
	}
	args := argsOf(t, result)
	if argsContain(args, "other-pipelock") || argsContain(args, "/old/ws") {
		t.Fatalf("foreign binary or workspace survived: %v", args)
	}
	if !argsContain(args, "/new/ws") {
		t.Fatalf("current --workspace not rebuilt: %v", args)
	}
}

func TestNormalizeForeign_ContinueHTTPInfersTransport(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"},
	}
	result, err := wrapContinueServer(foreign, self, "")
	if err != nil {
		t.Fatalf("wrapContinueServer: %v", err)
	}
	meta, _ := result[mcpFieldPipelock].(map[string]interface{})
	if meta["original_url"] != "https://api.vendor.example/mcp" {
		t.Fatalf("recovered upstream not recorded: %#v", meta)
	}
	if meta["original_type"] != continueTypeStreamHTTP {
		t.Fatalf("continue should infer streamable-http, got %v", meta["original_type"])
	}
	if argsContain(argsOf(t, result), "other-pipelock") {
		t.Fatalf("foreign binary survived: %v", argsOf(t, result))
	}
}

// TestNormalizeForeign_RepeatInstallIdempotent proves the normalized result is a
// genuine self-wrap, so a SECOND install skips it (isWrappedBySelf) rather than
// wrapping it again.
func TestNormalizeForeign_RepeatInstallIdempotent(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "node", "server.js"},
	}
	result, _, _, err := wrapVscodeServer(foreign, self, "", t.TempDir(), "srv")
	if err != nil {
		t.Fatalf("wrapVscodeServer: %v", err)
	}
	if !isWrappedBySelf(result) {
		t.Fatalf("normalized result is not self-wrapped, so a repeat install would nest it: %#v", result)
	}
}

// TestNormalizeForeign_RoundTripRemovalRestoresRecoveredInner proves remove now
// unwinds fully to the recovered inner command, not the foreign wrapper.
func TestNormalizeForeign_RoundTripRemovalRestoresRecoveredInner(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	foreign := map[string]interface{}{
		mcpFieldType:    vsTypeStdio,
		mcpFieldCommand: foreignBinary,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "node", "server.js"},
	}
	result, meta, _, err := wrapVscodeServer(foreign, self, "", dir, "srv")
	if err != nil {
		t.Fatalf("wrapVscodeServer: %v", err)
	}
	mj, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	var mm interface{}
	if err := json.Unmarshal(mj, &mm); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	result[mcpFieldPipelock] = mm

	restored, _, err := unwrapVscodeServer(result, dir, "srv")
	if err != nil {
		t.Fatalf("unwrapVscodeServer: %v", err)
	}
	if restored[mcpFieldCommand] != "node" {
		t.Fatalf("restored command = %v, want the recovered inner node (not the foreign wrapper)", restored[mcpFieldCommand])
	}
	if got := commandArgStrings(restored[mcpFieldArgs]); len(got) != 1 || got[0] != "server.js" {
		t.Fatalf("restored args = %v, want [server.js]", got)
	}
}

// TestNormalizeForeign_NonForeignPassThrough is the positive clean case: a bare
// server and a genuine self-wrapper are returned by the normalizer unchanged, so
// ordinary installs are unaffected.
func TestNormalizeForeign_NonForeignPassThrough(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	bare := map[string]interface{}{
		mcpFieldCommand: "node",
		mcpFieldArgs:    []interface{}{"server.js"},
	}
	got, err := normalizeForeignWrapper(bare, mcpHTTPWrapType)
	if err != nil {
		t.Fatalf("normalizeForeignWrapper(bare): %v", err)
	}
	if got[mcpFieldCommand] != "node" {
		t.Fatalf("bare server was altered: %#v", got)
	}

	selfWrap := map[string]interface{}{
		mcpFieldCommand: self,
		mcpFieldArgs:    []interface{}{"mcp", "proxy", "--", "node"},
	}
	got, err = normalizeForeignWrapper(selfWrap, mcpHTTPWrapType)
	if err != nil {
		t.Fatalf("normalizeForeignWrapper(self): %v", err)
	}
	if got[mcpFieldCommand] != self {
		t.Fatalf("self-wrapper was altered: %#v", got)
	}
	// OpenCode variant: a non-foreign array command is returned unchanged.
	bareOC := map[string]interface{}{mcpFieldCommand: []interface{}{"node", "server.js"}}
	gotOC, err := normalizeForeignOpenCodeWrapper(bareOC)
	if err != nil {
		t.Fatalf("normalizeForeignOpenCodeWrapper(bare): %v", err)
	}
	if cmd := commandArgStrings(gotOC[mcpFieldCommand]); len(cmd) != 2 || cmd[0] != "node" {
		t.Fatalf("bare opencode command altered: %#v", gotOC)
	}
}
