// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"strings"
	"testing"
)

func TestReplayCmd_RequiresConfig(t *testing.T) {
	cmd := replayCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--sessions", "/tmp/some-sessions"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --config is not provided")
	}
	if !strings.Contains(err.Error(), "--config") {
		t.Errorf("expected error to mention --config, got: %v", err)
	}
}

func TestReplayCmd_RequiresSessions(t *testing.T) {
	cmd := replayCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--config", "/tmp/candidate.yaml"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --sessions is not provided")
	}
	if !strings.Contains(err.Error(), "--sessions") {
		t.Errorf("expected error to mention --sessions, got: %v", err)
	}
}

func TestDecodeReplayEscrowPrivateKey(t *testing.T) {
	empty, err := decodeReplayEscrowPrivateKey("")
	if err != nil {
		t.Fatalf("decodeReplayEscrowPrivateKey empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty key len = %d, want 0", len(empty))
	}
	key, err := decodeReplayEscrowPrivateKey(strings.Repeat("0a", 32))
	if err != nil {
		t.Fatalf("decodeReplayEscrowPrivateKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
	if _, err := decodeReplayEscrowPrivateKey("not-hex"); err == nil {
		t.Fatal("expected invalid hex error")
	}
	if _, err := decodeReplayEscrowPrivateKey("abcd"); err == nil {
		t.Fatal("expected invalid length error")
	}
}
