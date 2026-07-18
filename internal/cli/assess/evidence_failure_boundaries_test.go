// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadEvidenceSourcesRejectsMalformedReports(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr string
	}{
		{
			name:    "simulation record",
			file:    "simulate.jsonl",
			wantErr: "parsing simulate evidence",
		},
		{
			name:    "audit score report",
			file:    "audit-score.jsonl",
			wantErr: "parsing audit-score evidence",
		},
		{
			name:    "installation report",
			file:    "verify-install.jsonl",
			wantErr: "parsing verify-install evidence",
		},
		{
			name:    "discovery report",
			file:    "discover.jsonl",
			wantErr: "parsing discover evidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDir := t.TempDir()
			evidenceDir := filepath.Join(runDir, "evidence")
			if err := os.Mkdir(evidenceDir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(evidenceDir, tt.file), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}

			sources, err := readEvidenceSources(runDir)
			if err == nil {
				t.Fatal("readEvidenceSources accepted malformed evidence")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want context %q", err, tt.wantErr)
			}
			if sources != (AssessSources{}) {
				t.Fatalf("sources = %#v, want no trusted sources after parse failure", sources)
			}
		})
	}
}

func TestWriteEvidenceJSONLRejectsUnencodableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	original := []byte("previous complete evidence\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeEvidenceJSONL(path, []any{
		map[string]string{"status": "valid"},
		map[string]float64{"invalid": math.Inf(1)},
		map[string]string{"status": "must-not-be-written"},
	})
	if err == nil {
		t.Fatal("writeEvidenceJSONL accepted an unsupported numeric value")
	}
	if !strings.Contains(err.Error(), "writing evidence line") {
		t.Fatalf("error = %q, want serialization context", err)
	}

	data, readErr := os.ReadFile(path) // #nosec G304 -- path is created inside t.TempDir.
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != string(original) {
		t.Fatalf("failed generation replaced complete evidence: %q", data)
	}
}

func TestWriteEvidenceJSONLRejectsUncreatableDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "evidence.jsonl")
	err := writeEvidenceJSONL(path, []any{map[string]string{"status": "valid"}})
	if err == nil {
		t.Fatal("writeEvidenceJSONL accepted a destination with no parent directory")
	}
	if !strings.Contains(err.Error(), "creating evidence file") {
		t.Fatalf("error = %q, want file creation context", err)
	}
}

func TestCheckAssessLicenseFailsClosedOnUntrustedInputs(t *testing.T) {
	t.Run("missing manifest", func(t *testing.T) {
		if checkAssessLicense(t.TempDir()) {
			t.Fatal("missing manifest enabled licensed output")
		}
	})

	t.Run("malformed manifest", func(t *testing.T) {
		runDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if checkAssessLicense(runDir) {
			t.Fatal("malformed manifest enabled licensed output")
		}
	})

	t.Run("unreadable config", func(t *testing.T) {
		runDir := t.TempDir()
		manifest := `{"config_file":"` + filepath.Join(runDir, "missing.yaml") + `"}`
		if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		if checkAssessLicense(runDir) {
			t.Fatal("unreadable config enabled licensed output")
		}
	})
}

func TestSortFindingsPlacesUnknownSeverityLast(t *testing.T) {
	findings := []Finding{
		{ID: "unknown", Severity: "urgent"},
		{ID: "info", Severity: assessSevInfo},
		{ID: "critical", Severity: assessSevCritical},
	}

	sortFindings(findings)

	if got := findings[len(findings)-1].ID; got != "unknown" {
		t.Fatalf("last finding = %q, want unknown severity last", got)
	}
}

func TestAssessmentPhasesRejectMalformedManifests(t *testing.T) {
	tests := []struct {
		name    string
		run     func(string) error
		wantErr string
	}{
		{
			name: "run",
			run: func(runDir string) error {
				return runAssessRun(runDir, false, nil)
			},
			wantErr: "parsing manifest",
		},
		{
			name: "finalize",
			run: func(runDir string) error {
				return runAssessFinalize(runDir, assessFinalizeOpts{})
			},
			wantErr: "parsing manifest",
		},
		{
			name: "verify",
			run: func(runDir string) error {
				_, err := runAssessVerify(runDir, "", "")
				return err
			},
			wantErr: "parsing manifest",
		},
		{
			name: "status",
			run: func(runDir string) error {
				_, _, err := loadAssessStatusManifest(runDir)
				return err
			},
			wantErr: "parsing manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}

			err := tt.run(runDir)
			if err == nil {
				t.Fatal("phase accepted malformed manifest")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want context %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunAssessVerifyRejectsArtifactPathEscape(t *testing.T) {
	parent := t.TempDir()
	runDir := filepath.Join(parent, "run")
	if err := os.Mkdir(runDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outsidePath := filepath.Join(parent, "outside.json")
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := AssessManifest{
		Status: assessStatusFinalized,
		Artifacts: map[string]string{
			"../outside.json": "attacker-controlled",
		},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	exitCode, err := runAssessVerify(runDir, "", "")
	if err == nil {
		t.Fatal("runAssessVerify accepted an artifact outside the run directory")
	}
	if exitCode != verifyExitTamperedArtifact {
		t.Fatalf("exit code = %d, want %d", exitCode, verifyExitTamperedArtifact)
	}
	if !strings.Contains(err.Error(), "path escapes run directory") {
		t.Fatalf("error = %q, want path escape context", err)
	}
}

func TestHashEvidenceFilesRejectsMissingRequiredEvidence(t *testing.T) {
	_, err := hashEvidenceFiles(t.TempDir(), []string{primitiveSimulate}, map[string]bool{})
	if err == nil {
		t.Fatal("hashEvidenceFiles accepted missing required evidence")
	}
	if !strings.Contains(err.Error(), "hashing simulate.jsonl") {
		t.Fatalf("error = %q, want evidence filename context", err)
	}
}

func TestWriteManifestReportsAtomicFilesystemFailures(t *testing.T) {
	t.Run("temporary file cannot be created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "manifest.json")
		err := writeManifest(path, &AssessManifest{})
		if err == nil {
			t.Fatal("writeManifest accepted a path with no parent directory")
		}
		if !strings.Contains(err.Error(), "writing manifest temp") {
			t.Fatalf("error = %q, want temporary file context", err)
		}
	})

	t.Run("temporary file cannot replace directory", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "manifest.json")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}

		err := writeManifest(path, &AssessManifest{})
		if err == nil {
			t.Fatal("writeManifest replaced a directory")
		}
		if !strings.Contains(err.Error(), "renaming manifest") {
			t.Fatalf("error = %q, want rename context", err)
		}
		if _, statErr := os.Stat(path + ".tmp"); !os.IsNotExist(statErr) {
			t.Fatalf("temporary manifest was not removed: %v", statErr)
		}
	})
}
