// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestClaudeHookCmd_PrintsUnverifiableBundleVersionWarning(t *testing.T) {
	// A test binary has no release stamp, so a bundle that declares a
	// min_pipelock merges with the unprovable-version warning. The hook must
	// print it on stderr and keep its stdout JSON contract intact.
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	bundleYAML := []byte(`format_version: 1
name: claude-warn-bundle
version: "2026.03.1"
author: Test Author
description: A bundle that declares a minimum version
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: claude-warn-rule
    type: dlp
    status: stable
    name: Claude Warn Rule
    description: Detects a fixture token no other test uses
    severity: high
    confidence: high
    pattern:
      regex: "zz-claude-warning-fixture-[0-9]{6}"
`)
	bundleDir := filepath.Join(dataHome, "pipelock", "rules", "claude-warn-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundleYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundleYAML)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "local:/tmp/claude-warn-rules",
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Unsigned:         true,
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatal(err)
	}

	input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la","description":"list files"},"tool_use_id":"t1"}`
	cmd := ClaudeCmd()
	cmd.SetArgs([]string{"hook"})
	cmd.SetIn(bytes.NewReader([]byte(input)))
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v\nstderr:\n%s", err, errOut.String())
	}
	if !strings.Contains(errOut.String(), `warning: bundle "claude-warn-bundle" loaded although min_pipelock`) {
		t.Fatalf("claude hook did not print the unprovable-version warning to stderr\nstderr:\n%s", errOut.String())
	}
	// stdout must remain exactly one hook response: an allow with no leaked
	// warning text before or after it.
	var resp claudeCodeResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &resp); err != nil {
		t.Fatalf("stdout is not a single hook response JSON document: %v\nstdout:\n%s", err, out.String())
	}
	if resp.HookSpecificOutput.PermissionDecision != decisionAllow {
		t.Fatalf("permission decision = %q, want %q", resp.HookSpecificOutput.PermissionDecision, decisionAllow)
	}
}
