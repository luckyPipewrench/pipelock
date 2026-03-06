// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/report"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testReportTitle   = "Pipelock Agent Egress Report"
	testReportVersion = "0.3.5"
)

// fixtureReportJSONL mirrors the fixture in internal/report/report_test.go.
const fixtureReportJSONL = `{"level":"info","time":"2026-03-05T10:00:00Z","component":"pipelock","event":"startup","listen":":8888","mode":"balanced","version":"0.3.5","config_hash":"abc123","message":"pipelock started"}
{"level":"info","time":"2026-03-05T10:00:01Z","component":"pipelock","event":"allowed","method":"GET","url":"https://api.example.com/data","client_ip":"10.0.0.1","request_id":"req-001","status_code":200,"size_bytes":1234,"message":"request allowed"}
{"level":"warn","time":"2026-03-05T10:00:02Z","component":"pipelock","event":"blocked","method":"GET","url":"https://evil.com/exfil?key=secret","client_ip":"10.0.0.1","request_id":"req-002","scanner":"dlp","reason":"AWS key pattern matched","mitre_technique":"T1048","message":"request blocked"}
{"level":"warn","time":"2026-03-05T10:00:03Z","component":"pipelock","event":"response_scan","url":"https://docs.example.com","client_ip":"10.0.0.1","request_id":"req-003","action":"warn","match_count":2,"patterns":["ignore_instructions","system_prompt"],"mitre_technique":"T1059","message":"response scan detected prompt injection"}
{"level":"info","time":"2026-03-05T10:00:04Z","component":"pipelock","event":"config_reload","status":"success","detail":"mode=strict","config_hash":"def456","message":"configuration reloaded"}
{"level":"warn","time":"2026-03-05T10:00:05Z","component":"pipelock","event":"chain_detection","pattern":"read-then-exec","severity":"high","action":"warn","tool":"execute_command","session":"sess-1","mitre_technique":"T1059","message":"chain pattern detected"}
{"level":"info","time":"2026-03-05T10:00:06Z","component":"pipelock","event":"kill_switch_deny","transport":"http","endpoint":"/fetch","source":"api","deny_message":"emergency shutdown","client_ip":"10.0.0.1","message":"kill switch denied request"}
`

// writeFixtureFile writes the JSONL fixture to a temp file and returns the path.
func writeFixtureFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(fixtureReportJSONL), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestReportCmd_HTMLStdout(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --input file: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, testReportTitle) {
		t.Error("expected report title in HTML output")
	}
	if !strings.Contains(out, "<!DOCTYPE html>") && !strings.Contains(out, "<html") {
		t.Error("expected HTML document in output")
	}
	// Risk should be red (kill_switch_deny event present).
	if !strings.Contains(out, "HIGH RISK") && !strings.Contains(out, "red") {
		t.Error("expected red risk indicator in HTML")
	}
}

func TestReportCmd_JSONStdout(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --format json: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if rpt.Title != testReportTitle {
		t.Errorf("expected title %q, got %q", testReportTitle, rpt.Title)
	}
	if rpt.Version != testReportVersion {
		t.Errorf("expected version %q, got %q", testReportVersion, rpt.Version)
	}
	if rpt.Risk != report.RiskRed {
		t.Errorf("expected red risk, got %q", rpt.Risk)
	}
	if rpt.Summary.TotalEvents != 7 {
		t.Errorf("expected 7 events, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_Stdin(t *testing.T) {
	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader(fixtureReportJSONL))
	cmd.SetArgs([]string{"--input", "-", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --input -: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON from stdin: %v", err)
	}
	if rpt.Summary.TotalEvents != 7 {
		t.Errorf("expected 7 events from stdin, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_OutputFile(t *testing.T) {
	inputPath := writeFixtureFile(t)
	outputPath := filepath.Join(t.TempDir(), "report.html")

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", inputPath, "-o", outputPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report -o file: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Error("output file is empty")
	}

	data, err := os.ReadFile(filepath.Clean(outputPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), testReportTitle) {
		t.Error("expected title in output file")
	}
}

func TestReportCmd_Bundle(t *testing.T) {
	inputPath := writeFixtureFile(t)
	bundleDir := filepath.Join(t.TempDir(), "bundle")

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", inputPath, "--format", "bundle", "-o", bundleDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --format bundle: %v", err)
	}

	// Verify 3 files: report.html, report.json, manifest.json.
	for _, name := range []string{"report.html", "report.json", "manifest.json"} {
		info, err := os.Stat(filepath.Join(bundleDir, name))
		if err != nil {
			t.Errorf("file %s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// No signature file without --sign.
	sigPath := filepath.Join(bundleDir, "manifest.json"+signing.SigExtension)
	if _, err := os.Stat(sigPath); err == nil {
		t.Error("unexpected .sig file without --sign")
	}
}

func TestReportCmd_BundleSigned(t *testing.T) {
	inputPath := writeFixtureFile(t)
	bundleDir := filepath.Join(t.TempDir(), "signed-bundle")

	// Set up a temporary keystore with a test agent.
	ksDir := t.TempDir()
	ks := signing.NewKeystore(ksDir)
	_, err := ks.GenerateAgent("test-agent")
	if err != nil {
		t.Fatalf("generating test agent key: %v", err)
	}

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--input", inputPath,
		"--format", "bundle",
		"-o", bundleDir,
		"--sign",
		"--agent", "test-agent",
		"--keystore", ksDir,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --sign: %v", err)
	}

	// Verify 4 files: report.html, report.json, manifest.json, manifest.json.sig.
	for _, name := range []string{"report.html", "report.json", "manifest.json", "manifest.json" + signing.SigExtension} {
		info, err := os.Stat(filepath.Join(bundleDir, name))
		if err != nil {
			t.Errorf("file %s missing: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// Verify signature validates.
	pubKey, err := ks.LoadPublicKey("test-agent")
	if err != nil {
		t.Fatalf("loading public key: %v", err)
	}
	manifestPath := filepath.Join(bundleDir, "manifest.json")
	if err := signing.VerifyFile(manifestPath, "", pubKey); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestReportCmd_DaysFilter(t *testing.T) {
	// Create events spanning 2 days: one today, one 3 days ago.
	now := time.Now().UTC()
	oldTime := now.AddDate(0, 0, -3).Format(time.RFC3339)
	recentTime := now.Add(-1 * time.Minute).Format(time.RFC3339)

	jsonl := `{"level":"info","time":"` + oldTime + `","event":"blocked","scanner":"dlp","url":"https://old.example.com","message":"old block"}
{"level":"info","time":"` + recentTime + `","event":"blocked","scanner":"dlp","url":"https://recent.example.com","message":"recent block"}
`

	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(jsonl), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "json", "--days", "1"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --days 1: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Only the recent event should be included.
	if rpt.Summary.TotalEvents != 1 {
		t.Errorf("expected 1 event with --days 1, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_SinceFilter(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	// Events start at 10:00:00Z, filter from 10:00:03Z should give 4 events.
	cmd.SetArgs([]string{"--input", path, "--format", "json", "--since", "2026-03-05T10:00:03Z"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --since: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// Events at 10:00:03, 10:00:04, 10:00:05, 10:00:06 = 4 events.
	if rpt.Summary.TotalEvents != 4 {
		t.Errorf("expected 4 events with --since, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_EmptyInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report with empty input: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Risk != report.RiskGreen {
		t.Errorf("expected green risk for empty input, got %q", rpt.Risk)
	}
	if rpt.Summary.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_MissingInput(t *testing.T) {
	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --input is missing")
	}
	if !strings.Contains(err.Error(), "--input is required") {
		t.Errorf("expected --input error, got: %v", err)
	}
}

func TestReportCmd_SignRequiresBundle(t *testing.T) {
	path := writeFixtureFile(t)

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "html", "--sign"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --sign used without --format bundle")
	}
	if !strings.Contains(err.Error(), "--sign requires --format bundle") {
		t.Errorf("expected sign-requires-bundle error, got: %v", err)
	}
}

func TestReportCmd_BundleRequiresOutput(t *testing.T) {
	path := writeFixtureFile(t)

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "bundle"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --format bundle without --output")
	}
	if !strings.Contains(err.Error(), "--format bundle requires --output") {
		t.Errorf("expected bundle-requires-output error, got: %v", err)
	}
}

func TestReportCmd_InvalidFormat(t *testing.T) {
	path := writeFixtureFile(t)

	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "pdf"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported format error, got: %v", err)
	}
}

func TestReportCmd_CustomTitle(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", path, "--format", "json", "--title", "Custom Report"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --title: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Title != "Custom Report" {
		t.Errorf("expected title %q, got %q", "Custom Report", rpt.Title)
	}
}

func TestReportCmd_SinceDate(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	// All fixture events are on 2026-03-05. Using --since 2026-03-06 should yield 0 events.
	cmd.SetArgs([]string{"--input", path, "--format", "json", "--since", "2026-03-06"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --since date: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Summary.TotalEvents != 0 {
		t.Errorf("expected 0 events with --since 2026-03-06, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_UntilFilter(t *testing.T) {
	path := writeFixtureFile(t)

	var buf bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&bytes.Buffer{})
	// Until 10:00:03Z should include events at 10:00:00, 10:00:01, 10:00:02 = 3 events.
	cmd.SetArgs([]string{"--input", path, "--format", "json", "--until", "2026-03-05T10:00:03Z"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report --until: %v", err)
	}

	var rpt report.Report
	if err := json.Unmarshal(buf.Bytes(), &rpt); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rpt.Summary.TotalEvents != 3 {
		t.Errorf("expected 3 events with --until 10:00:03Z, got %d", rpt.Summary.TotalEvents)
	}
}

func TestReportCmd_StderrSummary(t *testing.T) {
	path := writeFixtureFile(t)

	var stderr bytes.Buffer
	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--input", path, "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("report: %v", err)
	}

	summary := stderr.String()
	if !strings.Contains(summary, "Report generated:") {
		t.Errorf("expected summary on stderr, got: %s", summary)
	}
	if !strings.Contains(summary, "red risk") {
		t.Errorf("expected 'red risk' in summary, got: %s", summary)
	}
}

func TestReportCmd_NonexistentInput(t *testing.T) {
	cmd := reportCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--input", filepath.Join(t.TempDir(), "nonexistent.jsonl")})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent input file")
	}
	if !strings.Contains(err.Error(), "opening input") {
		t.Errorf("expected opening input error, got: %v", err)
	}
}

func TestParseTimeFlag(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, time.Time)
	}{
		{
			name:  "RFC3339",
			input: "2026-03-05T10:00:00Z",
			check: func(t *testing.T, got time.Time) {
				t.Helper()
				want := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
				if !got.Equal(want) {
					t.Errorf("RFC3339: got %v, want %v", got, want)
				}
			},
		},
		{
			name:  "date only",
			input: "2026-03-05",
			check: func(t *testing.T, got time.Time) {
				t.Helper()
				want := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
				if !got.Equal(want) {
					t.Errorf("date: got %v, want %v", got, want)
				}
			},
		},
		{
			name:    "invalid",
			input:   "not-a-date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimeFlag(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, got)
		})
	}
}
