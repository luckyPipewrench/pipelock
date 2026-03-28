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
