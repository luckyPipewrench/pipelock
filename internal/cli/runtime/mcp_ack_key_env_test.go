// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAckKeyWithheldFromChild(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		env     []string
		wantErr string
	}{
		{"no key", "", []string{"PIPELOCK_TEST_ACK_KEY=x"}, ""},
		{"file key", "file:/run/pipelock/ack.key", []string{"PIPELOCK_TEST_ACK_KEY=x"}, ""},
		{"dedicated variable not forwarded", "${PIPELOCK_TEST_ACK_KEY}", []string{"API_TOKEN=x"}, ""},
		{"forwarded by override", "${PIPELOCK_TEST_ACK_KEY}", []string{"API_TOKEN=x", "PIPELOCK_TEST_ACK_KEY=x"}, "acknowledgment key"},
		{"forwarded with other case", "${PIPELOCK_TEST_ACK_KEY}", []string{"pipelock_test_ack_key=x"}, "acknowledgment key"},
		{"forwarded as unset marker", "${PIPELOCK_TEST_ACK_KEY}", []string{"PIPELOCK_TEST_ACK_KEY"}, "acknowledgment key"},
		{"system variable every child gets", "${HOME}", nil, "every MCP server process receives"},
		{"empty reference is not a variable", "${}", []string{"PIPELOCK_TEST_ACK_KEY=x"}, ""},
		{"unterminated reference is not a variable", "${PIPELOCK_TEST_ACK_KEY", []string{"PIPELOCK_TEST_ACK_KEY=x"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ackKeyWithheldFromChild(tt.source, tt.env)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// A real MCP server process does not receive a dedicated acknowledgment key
// variable from Pipelock's own environment, and naming it with --env refuses
// the launch before the server starts. The key is synthetic.
func TestMCPServerProcessDoesNotReceiveAckKey(t *testing.T) {
	if runtime.GOOS == windowsOS {
		t.Skip("uses a POSIX shell child")
	}
	const name = "PIPELOCK_TEST_ACK_KEY_CHILD"
	key := "synthetic-acknowledgment-key-child-" + "0123456789"
	t.Setenv(name, key)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\nmode: balanced\nmcp_tool_scanning:\n  enabled: true\n  action: warn\n  acknowledgment_key: \"${"+name+"}\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	envOut := filepath.Join(dir, "child.env")
	script := "env > " + envOut

	_, stderr, err := runMCPProxyCommandWithInput(t, []string{"proxy", "--config", cfgPath, "--", "/bin/sh", "-c", script}, "")
	if err != nil {
		t.Fatalf("proxy: %v\n%s", err, stderr)
	}
	got, readErr := os.ReadFile(filepath.Clean(envOut))
	if readErr != nil {
		t.Fatalf("server process did not run: %v\n%s", readErr, stderr)
	}
	if !strings.Contains(string(got), "PATH=") {
		t.Fatalf("captured environment looks empty, so absence proves nothing:\n%s", got)
	}
	if strings.Contains(string(got), key) || strings.Contains(string(got), name) {
		t.Fatalf("server process received the acknowledgment key:\n%s", got)
	}

	if err := os.Remove(envOut); err != nil {
		t.Fatal(err)
	}
	_, stderr, err = runMCPProxyCommandWithInput(t, []string{"proxy", "--config", cfgPath, "--env", name, "--", "/bin/sh", "-c", script}, "")
	if err == nil || !strings.Contains(err.Error(), "acknowledgment key") {
		t.Fatalf("--env %s was not refused: err=%v\n%s", name, err, stderr)
	}
	if strings.Contains(err.Error()+stderr, key) {
		t.Fatalf("refusal exposes the key: %v\n%s", err, stderr)
	}
	if _, statErr := os.Stat(envOut); !os.IsNotExist(statErr) {
		t.Fatalf("server process started despite the refusal: %v", statErr)
	}
}
