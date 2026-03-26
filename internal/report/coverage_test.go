// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testEvBlocked        = "blocked"
	testEvAllowed        = "allowed"
	testScannerDLP       = "dlp"
	testClientIPCoverage = "10.0.0.1"
	testClientIPAlt      = "10.0.0.2"
)

func TestRenderHTML_RiskLevelColors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		risk RiskRating
		want string // substring expected in output
	}{
		{"green risk", RiskGreen, "LOW RISK"},
		{"yellow risk", RiskYellow, "MODERATE"},
		{"red risk", RiskRed, "HIGH RISK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rpt := &Report{
				Title:        "Test Report",
				Generated:    time.Now().UTC(),
				Version:      "1.0.0",
				Risk:         tt.risk,
				ConfigHashes: []string{},
				Categories:   []CategoryStats{},
				Domains:      []DomainStats{},
				Timeline:     []TimeBucket{},
				Evidence:     []Event{},
			}
			var buf bytes.Buffer
			if err := RenderHTML(&buf, rpt); err != nil {
				t.Fatalf("RenderHTML() error: %v", err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output missing %q for risk %q", tt.want, tt.risk)
			}
		})
	}
}

func TestRenderHTML_WithTimeline(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	rpt := &Report{
		Title:        "Timeline Report",
		Generated:    now,
		Version:      "1.0.0",
		Risk:         RiskGreen,
		ConfigHashes: []string{"abc"},
		TimeRange:    TimeRange{Start: now.Add(-time.Hour), End: now},
		Summary:      Summary{TotalEvents: 5, Allowed: 5, UniqueDomains: 2},
		Categories:   []CategoryStats{},
		Domains:      []DomainStats{},
		Timeline: []TimeBucket{
			{Start: now.Add(-time.Hour), Allowed: 3},
			{Start: now.Add(-30 * time.Minute), Allowed: 2},
		},
		Evidence: []Event{},
	}
	var buf bytes.Buffer
	if err := RenderHTML(&buf, rpt); err != nil {
		t.Fatalf("RenderHTML() error: %v", err)
	}
	// HTML output should be non-trivial.
	if buf.Len() < 100 {
		t.Errorf("HTML output too short: %d bytes", buf.Len())
	}
}

func TestRenderHTML_EvidenceInOutput(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	rpt := &Report{
		Title:        "Evidence Report",
		Generated:    now,
		Version:      "1.0.0",
		Risk:         RiskYellow,
		ConfigHashes: []string{},
		Categories:   []CategoryStats{},
		Domains:      []DomainStats{},
		Timeline:     []TimeBucket{},
		Evidence: []Event{
			{Time: now, Event: testEvBlocked, Scanner: testScannerDLP, Reason: "test pattern"},
		},
	}
	var buf bytes.Buffer
	if err := RenderHTML(&buf, rpt); err != nil {
		t.Fatalf("RenderHTML() error: %v", err)
	}
	if !strings.Contains(buf.String(), "test pattern") {
		t.Error("evidence event should appear in HTML")
	}
}

func TestWriteBundle_Success(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "bundle")
	now := time.Now().UTC()
	rpt := &Report{
		Title:        "Bundle Test",
		Generated:    now,
		Version:      "1.0.0",
		Risk:         RiskGreen,
		ConfigHashes: []string{},
		Categories:   []CategoryStats{},
		Domains:      []DomainStats{},
		Timeline:     []TimeBucket{},
		Evidence:     []Event{},
	}

	if err := WriteBundle(dir, rpt, nil); err != nil {
		t.Fatalf("WriteBundle() error: %v", err)
	}

	// Verify all files exist.
	for _, name := range []string{fileReportHTML, fileReportJSON, fileManifest} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing file %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// Verify manifest JSON parses.
	manifestData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, fileManifest)))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if len(m.Files) != 2 {
		t.Errorf("manifest files = %d, want 2", len(m.Files))
	}
}

func TestWriteBundle_WithSignature(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "signed-bundle")
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	rpt := &Report{
		Title:        "Signed Bundle Test",
		Generated:    time.Now().UTC(),
		Version:      "1.0.0",
		Risk:         RiskGreen,
		ConfigHashes: []string{},
		Categories:   []CategoryStats{},
		Domains:      []DomainStats{},
		Timeline:     []TimeBucket{},
		Evidence:     []Event{},
	}

	if err := WriteBundle(dir, rpt, privKey); err != nil {
		t.Fatalf("WriteBundle() error: %v", err)
	}

	// Verify signature file exists.
	sigPath := filepath.Join(dir, fileManifest+".sig")
	info, err := os.Stat(sigPath)
	if err != nil {
		t.Fatalf("missing signature file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("signature file is empty")
	}
}

func TestWriteBundle_ReadOnlyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() {
		// Restore write permission so t.TempDir cleanup can remove the directory.
		_ = os.Chmod(roDir, os.FileMode(0o500|0o200)) //nolint:gosec // test cleanup needs write permission
	})

	rpt := &Report{
		Title:        "Error Test",
		Generated:    time.Now().UTC(),
		ConfigHashes: []string{},
		Categories:   []CategoryStats{},
		Domains:      []DomainStats{},
		Timeline:     []TimeBucket{},
		Evidence:     []Event{},
	}

	// The target is inside the read-only dir, so MkdirAll should fail.
	err := WriteBundle(filepath.Join(roDir, "subdir"), rpt, nil)
	if err == nil {
		t.Fatal("expected error for read-only directory, got nil")
	}
}

func TestGenerate_EmptyInput(t *testing.T) {
	t.Parallel()

	rpt, err := Generate(strings.NewReader(""), ParseOptions{}, Options{})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if rpt.Risk != RiskGreen {
		t.Errorf("empty input should produce green risk, got %q", rpt.Risk)
	}
	if rpt.Summary.TotalEvents != 0 {
		t.Errorf("empty input should have 0 events, got %d", rpt.Summary.TotalEvents)
	}
}

func TestGenerate_MalformedLines(t *testing.T) {
	t.Parallel()

	input := "not json at all\n{\"level\":\"info\",\"time\":\"2026-03-05T10:00:00Z\",\"event\":\"allowed\"}\nalso bad\n"
	rpt, err := Generate(strings.NewReader(input), ParseOptions{}, Options{})
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if rpt.Summary.SkippedLines != 2 {
		t.Errorf("skipped lines = %d, want 2", rpt.Summary.SkippedLines)
	}
}

func TestBuildAgentBreakdown(t *testing.T) {
	t.Parallel()

	events := []Event{
		{Event: testEvAllowed, ClientIP: testClientIPCoverage},
		{Event: testEvAllowed, ClientIP: testClientIPCoverage},
		{Event: testEvBlocked, ClientIP: testClientIPCoverage, Scanner: testScannerDLP},
		{Event: testEvAllowed, ClientIP: testClientIPAlt},
		{Event: testEvBlocked, ClientIP: testClientIPAlt, Scanner: testScannerDLP},
		{Event: testEvBlocked, ClientIP: testClientIPAlt, Scanner: testScannerDLP},
		// Admin events should be skipped.
		{Event: eventStartup, ClientIP: testClientIPCoverage},
		// Events without ClientIP should be skipped.
		{Event: testEvAllowed},
	}

	result := buildAgentBreakdown(events, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(result))
	}

	// Sorted by blocks descending.
	if result[0].Agent != testClientIPAlt {
		t.Errorf("first agent should be %q (most blocks), got %q", testClientIPAlt, result[0].Agent)
	}
	if result[0].Blocks != 2 {
		t.Errorf("agent %q blocks = %d, want 2", result[0].Agent, result[0].Blocks)
	}
	if result[0].Allowed != 1 {
		t.Errorf("agent %q allowed = %d, want 1", result[0].Agent, result[0].Allowed)
	}
}

func TestBuildAgentBreakdown_Redact(t *testing.T) {
	t.Parallel()

	events := []Event{
		{Event: testEvAllowed, ClientIP: testClientIPCoverage},
	}
	result := buildAgentBreakdown(events, true)
	if len(result) != 1 {
		t.Fatalf("expected 1 agent entry, got %d", len(result))
	}
	if result[0].Agent == testClientIPCoverage {
		t.Error("agent IP should be redacted")
	}
}

func TestBuildAgentBreakdown_Cap10(t *testing.T) {
	t.Parallel()

	var events []Event
	for i := range 15 {
		events = append(events, Event{
			Event:    testEvAllowed,
			ClientIP: "10.0." + strings.Repeat("0", 0) + "." + itoa(i+1),
		})
	}

	result := buildAgentBreakdown(events, false)
	if len(result) > 10 {
		t.Errorf("agent breakdown should be capped at 10, got %d", len(result))
	}
}

// itoa is a simple int-to-string helper for test readability.
func itoa(n int) string {
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
