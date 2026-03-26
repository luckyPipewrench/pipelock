// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// logsRoot creates a minimal root command with the logs subcommand registered.
func logsRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "pipelock",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(LogsCmd())
	return root
}

func TestLogsCmd_FollowMode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "follow.log")

	// Write an initial line
	if err := os.WriteFile(logPath, []byte("{\"event\":\"allowed\",\"url\":\"https://first.com\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := logsRoot()
	cmd.SetContext(ctx)
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"logs", "--file", logPath, "--follow"})

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	// Give the command time to read initial content and enter follow mode
	time.Sleep(200 * time.Millisecond)

	// Append a new line while follow mode is active
	f, err := os.OpenFile(filepath.Clean(logPath), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		cancel()
		t.Fatalf("opening log for append: %v", err)
	}
	_, _ = f.WriteString("{\"event\":\"blocked\",\"url\":\"https://appended.com\"}\n")
	_ = f.Close()

	// Give follow mode time to pick up the new line
	time.Sleep(500 * time.Millisecond)

	// Cancel to break out via context
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logs follow did not exit after context cancel")
	}

	output := buf.String()
	if !strings.Contains(output, "first.com") {
		t.Error("expected initial line in output")
	}
	if !strings.Contains(output, "appended.com") {
		t.Error("expected appended line in follow output")
	}
}

func TestLogsCmd_FollowWithFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "follow-filter.log")

	if err := os.WriteFile(logPath, []byte("{\"event\":\"allowed\",\"url\":\"https://ok.com\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := logsRoot()
	cmd.SetContext(ctx)
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"logs", "--file", logPath, "--follow", "--filter", "blocked"})

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute()
	}()

	time.Sleep(200 * time.Millisecond)

	// Append lines: one allowed (filtered), one blocked (shown)
	f, err := os.OpenFile(filepath.Clean(logPath), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		cancel()
		t.Fatalf("opening log for append: %v", err)
	}
	_, _ = f.WriteString("{\"event\":\"allowed\",\"url\":\"https://skip.com\"}\n")
	_, _ = f.WriteString("{\"event\":\"blocked\",\"url\":\"https://caught.com\"}\n")
	_ = f.Close()

	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logs follow did not exit")
	}

	output := buf.String()
	if strings.Contains(output, "ok.com") {
		t.Error("expected initial allowed line to be filtered out")
	}
	if strings.Contains(output, "skip.com") {
		t.Error("expected appended allowed line to be filtered out")
	}
	if !strings.Contains(output, "caught.com") {
		t.Error("expected blocked line in output")
	}
}

func TestLogsCmd_FollowContextCancel(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cancel.log")

	if err := os.WriteFile(logPath, []byte("line1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Cancel quickly to test the context check path
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	cmd := logsRoot()
	cmd.SetContext(ctx)
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"logs", "--file", logPath, "--follow"})

	err := cmd.Execute()
	if err != nil {
		t.Errorf("expected nil error on context cancel, got: %v", err)
	}
}

func TestMatchFilter_JSONEvent(t *testing.T) {
	line := `{"event":"blocked","url":"https://evil.com"}`

	if !matchFilter(line, "blocked") {
		t.Error("expected blocked filter to match")
	}
	if matchFilter(line, "allowed") {
		t.Error("expected allowed filter not to match")
	}
}

func TestMatchFilter_NonJSON(t *testing.T) {
	line := "some plain text with blocked in it"

	if !matchFilter(line, "blocked") {
		t.Error("expected string contains match for non-JSON")
	}
	if matchFilter(line, "missing") {
		t.Error("expected no match when substring not present")
	}
}

func TestMatchFilter_JSONNoEventField(t *testing.T) {
	// JSON that parses successfully but has no "event" field.
	line := `{"url":"https://example.com","status":200}`

	if matchFilter(line, "allowed") {
		t.Error("expected no match when JSON has no event field")
	}
}

func TestMatchFilter_JSONEventWrongType(t *testing.T) {
	// JSON with "event" field that is not a string.
	line := `{"event":42,"url":"https://example.com"}`

	if matchFilter(line, "42") {
		t.Error("expected no match when event field is not a string")
	}
}
