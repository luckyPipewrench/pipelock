// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testToolName = "pipelock test"
	testVersion  = "1.0.0"
	testSnippet  = "AKIA" + "IOSFODNN7EXAMPLE" // split to avoid gosec G101
)

func TestNew(t *testing.T) {
	log := New(testToolName, testVersion)

	if log.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", log.Version, "2.1.0")
	}
	if log.Schema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("Schema = %q, want schema URL", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("Runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != testToolName {
		t.Errorf("Name = %q, want %q", log.Runs[0].Tool.Driver.Name, testToolName)
	}
	if log.Runs[0].Tool.Driver.Version != testVersion {
		t.Errorf("Version = %q, want %q", log.Runs[0].Tool.Driver.Version, testVersion)
	}
}

func TestAddRule(t *testing.T) {
	log := New(testToolName, testVersion)

	idx0 := log.AddRule("DLP-001", "AWS Key")
	if idx0 != 0 {
		t.Errorf("first AddRule index = %d, want 0", idx0)
	}

	idx1 := log.AddRule("DLP-002", "GitHub Token")
	if idx1 != 1 {
		t.Errorf("second AddRule index = %d, want 1", idx1)
	}

	// Duplicate returns existing index.
	idx0dup := log.AddRule("DLP-001", "AWS Key")
	if idx0dup != 0 {
		t.Errorf("duplicate AddRule index = %d, want 0", idx0dup)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("rule count = %d, want 2", len(rules))
	}
}

func TestAddResult(t *testing.T) {
	t.Run("with file and line and snippet", func(t *testing.T) {
		log := New(testToolName, testVersion)
		log.AddRule("DLP-001", "AWS Key")
		log.AddResult("DLP-001", 0, "error", "Secret detected", "src/config.go", 42, testSnippet)

		results := log.Runs[0].Results
		if len(results) != 1 {
			t.Fatalf("results = %d, want 1", len(results))
		}
		r := results[0]
		if r.RuleID != "DLP-001" {
			t.Errorf("RuleID = %q, want %q", r.RuleID, "DLP-001")
		}
		if r.Level != "error" {
			t.Errorf("Level = %q, want %q", r.Level, "error")
		}
		if len(r.Locations) != 1 {
			t.Fatalf("Locations = %d, want 1", len(r.Locations))
		}
		loc := r.Locations[0]
		if loc.PhysicalLocation.ArtifactLocation.URI != "src/config.go" {
			t.Errorf("URI = %q, want %q", loc.PhysicalLocation.ArtifactLocation.URI, "src/config.go")
		}
		if loc.PhysicalLocation.Region == nil {
			t.Fatal("Region = nil, want non-nil")
		}
		if loc.PhysicalLocation.Region.StartLine != 42 {
			t.Errorf("StartLine = %d, want 42", loc.PhysicalLocation.Region.StartLine)
		}
		if loc.PhysicalLocation.Region.Snippet == nil || loc.PhysicalLocation.Region.Snippet.Text != testSnippet {
			t.Errorf("Snippet mismatch")
		}
	})

	t.Run("without file", func(t *testing.T) {
		log := New(testToolName, testVersion)
		log.AddRule("SEC-001", "Finding")
		log.AddResult("SEC-001", 0, "warning", "No file", "", 0, "")

		r := log.Runs[0].Results[0]
		if len(r.Locations) != 0 {
			t.Errorf("Locations = %d, want 0 (no file)", len(r.Locations))
		}
	})

	t.Run("with file but no line", func(t *testing.T) {
		log := New(testToolName, testVersion)
		log.AddRule("SEC-002", "Finding")
		log.AddResult("SEC-002", 0, "note", "File only", "README.md", 0, "")

		loc := log.Runs[0].Results[0].Locations[0]
		if loc.PhysicalLocation.Region != nil {
			t.Errorf("Region should be nil when line=0")
		}
	})

	t.Run("with file and line but no snippet", func(t *testing.T) {
		log := New(testToolName, testVersion)
		log.AddRule("SEC-003", "Finding")
		log.AddResult("SEC-003", 0, "error", "Line only", "main.go", 10, "")

		region := log.Runs[0].Results[0].Locations[0].PhysicalLocation.Region
		if region == nil {
			t.Fatal("Region = nil, want non-nil")
		}
		if region.Snippet != nil {
			t.Errorf("Snippet should be nil when empty")
		}
	})
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", LevelError},
		{"high", LevelError},
		{"warning", LevelWarning},
		{"medium", LevelWarning},
		{"low", LevelNote},
		{"info", LevelNote},
		{"", LevelNote},
		{"unknown", LevelNote},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityToLevel(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityToLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	log := New(testToolName, testVersion)
	log.AddRule("DLP-001", "AWS Key")
	log.AddResult("DLP-001", 0, "error", "Secret detected", "app.go", 5, "key=AKIA...")

	var buf bytes.Buffer
	if err := log.Write(&buf); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Verify valid JSON.
	var parsed Log
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("parsed Version = %q, want %q", parsed.Version, "2.1.0")
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("parsed Runs = %d, want 1", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Results) != 1 {
		t.Errorf("parsed Results = %d, want 1", len(parsed.Runs[0].Results))
	}
	if len(parsed.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("parsed Rules = %d, want 1", len(parsed.Runs[0].Tool.Driver.Rules))
	}
}

func TestWriteToTarget_Stdout(t *testing.T) {
	log := New(testToolName, testVersion)
	log.AddRule("DLP-001", "AWS Key")

	var stdout, stderr bytes.Buffer
	if err := log.WriteToTarget(&stdout, &stderr, ""); err != nil {
		t.Fatalf("WriteToTarget error: %v", err)
	}
	if !strings.Contains(stdout.String(), `"version": "2.1.0"`) {
		t.Error("expected SARIF output on stdout")
	}
	if stderr.Len() != 0 {
		t.Errorf("expected empty stderr, got %q", stderr.String())
	}
}

func TestWriteToTarget_File(t *testing.T) {
	log := New(testToolName, testVersion)
	log.AddRule("DLP-001", "AWS Key")
	log.AddResult("DLP-001", 0, LevelError, "found", "x.go", 1, "")

	outPath := filepath.Join(t.TempDir(), "out.sarif")
	var stdout, stderr bytes.Buffer
	if err := log.WriteToTarget(&stdout, &stderr, outPath); err != nil {
		t.Fatalf("WriteToTarget error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout when writing to file, got %d bytes", stdout.Len())
	}
	if !strings.Contains(stderr.String(), "SARIF written to:") {
		t.Error("expected confirmation on stderr")
	}
	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(data), `"version": "2.1.0"`) {
		t.Error("expected SARIF content in file")
	}
}

func TestWriteToTarget_BadPath(t *testing.T) {
	log := New(testToolName, testVersion)
	var stdout, stderr bytes.Buffer
	// Write to a path inside a nonexistent directory.
	err := log.WriteToTarget(&stdout, &stderr, filepath.Join(t.TempDir(), "no", "such", "dir", "out.sarif"))
	if err == nil {
		t.Fatal("expected error for bad path")
	}
	if !strings.Contains(err.Error(), "creating SARIF output") {
		t.Errorf("expected 'creating SARIF output' error, got: %v", err)
	}
}
