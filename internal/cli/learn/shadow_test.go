// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/shadow"
)

func TestResolveShadowSessionsUsesExplicitDirAndRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	got, err := resolveShadowSessions(config.Defaults(), shadowFlags{sessionsDir: dir})
	if err != nil {
		t.Fatalf("resolveShadowSessions: %v", err)
	}
	if got != dir {
		t.Fatalf("sessions dir = %q, want %q", got, dir)
	}

	link := filepath.Join(t.TempDir(), "sessions-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := resolveShadowSessions(config.Defaults(), shadowFlags{sessionsDir: link}); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("resolve symlink error = %v, want symlink rejection", err)
	}
}

func TestFilterShadowDurationKeepsZeroTimestampAndRecentRecords(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	records := []capture.ReplayedRecord{
		{},
		{Timestamp: now.Add(-30 * time.Minute)},
		{Timestamp: now.Add(-2 * time.Hour)},
	}
	got := filterShadowDuration(records, now, time.Hour)
	if len(got) != 2 {
		t.Fatalf("filtered records = %d, want zero timestamp + recent", len(got))
	}
}

func TestRunDiffPrintsAndWritesMarkdown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	writeShadowReport(t, first, shadow.Report{
		ReportVersion: 1,
		ContractHash:  "sha256:a",
		TotalRecords:  10,
		NewBlocks:     1,
		Rules: []shadow.RuleStats{{
			RuleID:      "rule-a",
			Evaluations: 10,
			NewBlocks:   1,
		}},
	})
	writeShadowReport(t, second, shadow.Report{
		ReportVersion: 1,
		ContractHash:  "sha256:b",
		TotalRecords:  12,
		NewBlocks:     3,
		Rules: []shadow.RuleStats{{
			RuleID:      "rule-a",
			Evaluations: 12,
			NewBlocks:   3,
		}},
	})

	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := runDiff(cmd, first, second, ""); err != nil {
		t.Fatalf("runDiff stdout: %v", err)
	}
	if !strings.Contains(stdout.String(), "Shadow Diff") || !strings.Contains(stdout.String(), "+2") {
		t.Fatalf("stdout diff =\n%s", stdout.String())
	}

	out := filepath.Join(dir, "diff.md")
	if err := runDiff(cmd, first, second, out); err != nil {
		t.Fatalf("runDiff out: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("ReadFile diff: %v", err)
	}
	if !bytes.Contains(data, []byte("new_blocks_delta")) {
		t.Fatalf("written diff =\n%s", data)
	}
}

func writeShadowReport(t *testing.T, path string, report shadow.Report) {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal report: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile report: %v", err)
	}
}
