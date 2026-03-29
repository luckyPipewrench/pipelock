// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// testBuildVersion and testBuildSHA are stub build metadata for fixture writers.
const (
	testBuildVersion = "test"
	testBuildSHA     = "abc123"
)

// testCaptureSession is the session ID used across replay integration tests.
const testCaptureSession = "replay-test"

// writeFixtureCaptures writes two URL verdicts to sessionsDir: one originally
// allowed (api.example.com) and one originally blocked with a DLP finding
// (evil.example.com). Returns after the writer is closed and entries are flushed.
func writeFixtureCaptures(t *testing.T, sessionsDir string) {
	t.Helper()

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:           true,
			Dir:               sessionsDir,
			MaxEntriesPerFile: 100,
		},
		QueueSize:    64,
		BuildVersion: testBuildVersion,
		BuildSHA:     testBuildSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx := context.Background()

	// Record 1: api.example.com was allowed.
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface:      "forward",
		Transport:       "forward",
		SessionID:       testCaptureSession,
		RequestID:       "req-1",
		ConfigHash:      "original-hash",
		EffectiveAction: config.ActionAllow,
		Outcome:         capture.OutcomeClean,
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://api.example.com/safe",
		},
	})

	// Record 2: evil.example.com was blocked with a DLP finding.
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface:      "forward",
		Transport:       "forward",
		SessionID:       testCaptureSession,
		RequestID:       "req-2",
		ConfigHash:      "original-hash",
		EffectiveAction: config.ActionBlock,
		Outcome:         capture.OutcomeBlocked,
		RawFindings: []capture.Finding{
			{Kind: capture.KindDLP, Action: config.ActionBlock, PatternName: "test_dlp"},
		},
		EffectiveFindings: []capture.Finding{
			{Kind: capture.KindDLP, Action: config.ActionBlock, PatternName: "test_dlp"},
		},
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://evil.example.com/exfil",
		},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Writer.Close: %v", err)
	}
}

// writeCandidateConfig writes a minimal YAML config that blocks both test
// domains. Returns the path to the written file.
func writeCandidateConfig(t *testing.T) string {
	t.Helper()

	content := `mode: balanced
fetch_proxy:
  monitoring:
    blocklist:
      - api.example.com
      - evil.example.com
`
	path := filepath.Join(t.TempDir(), "candidate.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestReplayCmd_FullRoundTrip exercises the full replay CLI: write fixtures,
// run the replay command, and verify HTML + JSON reports are produced.
func TestReplayCmd_FullRoundTrip(t *testing.T) {
	sessionsDir := t.TempDir()
	writeFixtureCaptures(t, sessionsDir)

	configFile := writeCandidateConfig(t)

	reportDir := t.TempDir()
	htmlPath := filepath.Join(reportDir, "diff.html")
	jsonPath := filepath.Join(reportDir, "diff.json")

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", sessionsDir,
		"--report", htmlPath,
		"--report-json", jsonPath,
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nOutput: %s", err, buf.String())
	}

	// Verify stdout summary contains expected labels.
	output := buf.String()
	for _, want := range []string{"Records:", "New blocks:", "Unchanged:", "Candidate hash:"} {
		if !strings.Contains(output, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, output)
		}
	}

	// Verify HTML report exists and contains new_block.
	htmlData, err := os.ReadFile(filepath.Clean(htmlPath))
	if err != nil {
		t.Fatalf("ReadFile HTML: %v", err)
	}
	if !strings.Contains(string(htmlData), "new_block") {
		t.Error("HTML report missing 'new_block' change type")
	}

	// Verify JSON report exists and unmarshals to a valid DiffReport.
	jsonData, err := os.ReadFile(filepath.Clean(jsonPath))
	if err != nil {
		t.Fatalf("ReadFile JSON: %v", err)
	}
	var report capture.DiffReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		t.Fatalf("Unmarshal DiffReport: %v", err)
	}
	if report.TotalRecords != 2 {
		t.Errorf("TotalRecords: got %d, want 2", report.TotalRecords)
	}
	if report.NewBlocks != 1 {
		t.Errorf("NewBlocks: got %d, want 1", report.NewBlocks)
	}
	if report.Unchanged != 1 {
		t.Errorf("Unchanged: got %d, want 1", report.Unchanged)
	}
	if report.ReportVersion == 0 {
		t.Error("ReportVersion should be non-zero")
	}
	if report.CandidateConfigHash == "" {
		t.Error("CandidateConfigHash should be non-empty")
	}
}

// TestReplayCmd_InvalidConfig verifies that a nonexistent config file produces
// an error mentioning config loading.
func TestReplayCmd_InvalidConfig(t *testing.T) {
	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", "/tmp/nonexistent-config-12345.yaml",
		"--sessions", t.TempDir(),
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("expected error to mention config, got: %v", err)
	}
}

// TestReplayCmd_EmptySessions verifies that an empty sessions directory
// produces no error and zero records in the output.
func TestReplayCmd_EmptySessions(t *testing.T) {
	configFile := writeCandidateConfig(t)

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", t.TempDir(),
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nOutput: %s", err, buf.String())
	}

	output := buf.String()
	if !strings.Contains(output, "Records:       0") {
		t.Errorf("expected 0 records in output, got:\n%s", output)
	}
}

// TestReplayCmd_HTMLOnly verifies replay works with only --report (no JSON).
func TestReplayCmd_HTMLOnly(t *testing.T) {
	sessionsDir := t.TempDir()
	writeFixtureCaptures(t, sessionsDir)

	configFile := writeCandidateConfig(t)
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", sessionsDir,
		"--report", htmlPath,
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if _, err := os.Stat(htmlPath); err != nil {
		t.Fatalf("HTML report not created: %v", err)
	}
}

// TestReplayCmd_JSONOnly verifies replay works with only --report-json (no HTML).
func TestReplayCmd_JSONOnly(t *testing.T) {
	sessionsDir := t.TempDir()
	writeFixtureCaptures(t, sessionsDir)

	configFile := writeCandidateConfig(t)
	jsonPath := filepath.Join(t.TempDir(), "report.json")

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", sessionsDir,
		"--report-json", jsonPath,
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("JSON report not created: %v", err)
	}
}

// TestReplayCmd_NoReportFiles verifies replay works without any report flags
// (stdout-only summary).
func TestReplayCmd_NoReportFiles(t *testing.T) {
	sessionsDir := t.TempDir()
	writeFixtureCaptures(t, sessionsDir)

	configFile := writeCandidateConfig(t)

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", sessionsDir,
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Records:") {
		t.Errorf("expected summary in stdout, got:\n%s", output)
	}
}

// TestCmdPolicy_ReplaySubcommand verifies the top-level Cmd() includes the
// replay subcommand.
func TestCmdPolicy_ReplaySubcommand(t *testing.T) {
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"replay", "--help"})
	_ = cmd.Execute()

	help := buf.String()
	if !strings.Contains(help, "--config") {
		t.Error("replay help missing --config flag")
	}
	if !strings.Contains(help, "--sessions") {
		t.Error("replay help missing --sessions flag")
	}
	if !strings.Contains(help, "--report") {
		t.Error("replay help missing --report flag")
	}
}

// TestWriteReport_InvalidPath verifies that writeReport returns an error when
// the output path is in a nonexistent directory.
func TestWriteReport_InvalidPath(t *testing.T) {
	diff := &capture.DiffReport{ReportVersion: 1}
	err := writeReport("/nonexistent-dir/report.html", diff, capture.RenderDiffHTML)
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
	if !strings.Contains(err.Error(), "opening report file") {
		t.Errorf("expected 'opening report file' in error, got: %v", err)
	}
}

// TestHashFile verifies hashFile returns a valid hex-encoded SHA-256 digest.
func TestHashFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash, err := hashFile(path)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	// SHA-256 hex digest is always 64 characters.
	const sha256HexLen = 64
	if len(hash) != sha256HexLen {
		t.Errorf("hash length: got %d, want %d", len(hash), sha256HexLen)
	}
}

// TestReplayCmd_InvalidSessionsDir verifies that a nonexistent sessions
// directory produces an error mentioning replay.
func TestReplayCmd_InvalidSessionsDir(t *testing.T) {
	configFile := writeCandidateConfig(t)

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", "/tmp/nonexistent-sessions-dir-12345",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent sessions dir")
	}
	if !strings.Contains(err.Error(), "replaying sessions") {
		t.Errorf("expected error to mention 'replaying sessions', got: %v", err)
	}
}

// TestReplayCmd_BadReportPath verifies that an invalid report path returns
// an error mentioning writing.
func TestReplayCmd_BadReportPath(t *testing.T) {
	sessionsDir := t.TempDir()
	writeFixtureCaptures(t, sessionsDir)

	configFile := writeCandidateConfig(t)

	cmd := Cmd()
	cmd.SetArgs([]string{
		"replay",
		"--config", configFile,
		"--sessions", sessionsDir,
		"--report-json", "/nonexistent-dir/report.json",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON report path")
	}
	if !strings.Contains(err.Error(), "writing JSON report") {
		t.Errorf("expected error to mention 'writing JSON report', got: %v", err)
	}
}

// TestHashFile_Nonexistent verifies hashFile returns an error for missing files.
func TestHashFile_Nonexistent(t *testing.T) {
	_, err := hashFile("/tmp/nonexistent-file-12345.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "reading file") {
		t.Errorf("expected 'reading file' in error, got: %v", err)
	}
}
