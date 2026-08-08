// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The alert is the whole point of this command, so the metric must be written
// on every outcome, including the ones that also exit nonzero. A run that
// reports damage through its exit code but leaves the gauge stale would keep
// the alert quiet, which is the failure this feature exists to prevent.
func TestEvidenceDoctorWritesCorpusMetricOnEveryOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		seed      func(t *testing.T, dir string)
		wantCode  int
		wantGauge string
	}{
		{
			name: "clean corpus reports healthy",
			seed: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
				})
			},
			wantCode:  cliutil.ExitOK,
			wantGauge: "pipelock_evidence_corpus_integrity_ok 1",
		},
		{
			// A scan that could not cover the whole directory must publish
			// unhealthy. Absence of findings over a partial view is not
			// evidence of an intact chain, so a truncated scan reporting 1
			// would be the one reading an alert cannot distinguish from real
			// health.
			name: "incomplete scan reports unhealthy",
			seed: func(t *testing.T, dir string) {
				seedTruncatingCorpus(t, dir)
			},
			wantCode:  cliutil.ExitGeneral,
			wantGauge: "pipelock_evidence_corpus_integrity_ok 0",
		},
		{
			name: "damaged corpus reports unhealthy and still exits nonzero",
			seed: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-1.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 1, prev: "not-genesis"},
				})
			},
			wantCode:  cliutil.ExitGeneral,
			wantGauge: "pipelock_evidence_corpus_integrity_ok 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tt.seed(t, dir)
			metricPath := filepath.Join(t.TempDir(), "textfile", "pipelock_evidence_corpus.prom")

			cmd := Cmd()
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{"doctor", dir, "--prometheus-textfile", metricPath})

			err := cmd.Execute()
			gotCode := cliutil.ExitOK
			if err != nil {
				gotCode = cliutil.ExitCodeOf(err)
			}
			if gotCode != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (err=%v)", gotCode, tt.wantCode, err)
			}

			raw, readErr := os.ReadFile(filepath.Clean(metricPath))
			if readErr != nil {
				t.Fatalf("metric was not written: %v", readErr)
			}
			if !strings.Contains(string(raw), tt.wantGauge) {
				t.Fatalf("metric missing %q:\n%s", tt.wantGauge, raw)
			}
		})
	}
}

// A scan that cannot even start must still publish an unhealthy reading, or an
// auditor pointed at a vanished directory would look indistinguishable from a
// healthy corpus to the alert.
func TestEvidenceDoctorWritesUnhealthyMetricWhenScanCannotStart(t *testing.T) {
	t.Parallel()

	metricPath := filepath.Join(t.TempDir(), "pipelock_evidence_corpus.prom")
	missing := filepath.Join(t.TempDir(), "no-such-evidence-dir")

	cmd := Cmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"doctor", missing, "--prometheus-textfile", metricPath})

	if err := cmd.Execute(); err == nil {
		t.Fatal("a missing evidence directory was accepted")
	}

	raw, readErr := os.ReadFile(filepath.Clean(metricPath))
	if readErr != nil {
		t.Fatalf("metric was not written for a failed scan: %v", readErr)
	}
	if !strings.Contains(string(raw), "pipelock_evidence_corpus_integrity_ok 0") {
		t.Fatalf("failed scan did not report unhealthy:\n%s", raw)
	}
}

// If the metric cannot be published, the command must fail rather than exit
// zero. Reporting success while the alert's only input is missing is the same
// silent gap this feature was built to close, and it applies whether the scan
// itself succeeded or not.
func TestEvidenceDoctorFailsWhenMetricCannotBeWritten(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		seed func(t *testing.T, dir string)
	}{
		{
			name: "after a clean scan",
			seed: func(t *testing.T, dir string) {
				writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
					{session: "proxy", seq: 0, prev: recorder.GenesisHash},
				})
			},
		},
		{
			name: "after a scan that could not start",
			seed: func(*testing.T, string) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			tt.seed(t, dir)
			if tt.name == "after a scan that could not start" {
				dir = filepath.Join(dir, "no-such-evidence-dir")
			}

			// A regular file where the metric's parent directory belongs makes
			// the write fail without needing an injected fault.
			blocker := filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
				t.Fatalf("seed blocking file: %v", err)
			}

			cmd := Cmd()
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs([]string{"doctor", dir, "--prometheus-textfile", filepath.Join(blocker, "corpus.prom")})

			err := cmd.Execute()
			if err == nil {
				t.Fatal("command reported success although the metric was never published")
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d for an unpublishable metric", got, cliutil.ExitConfig)
			}
		})
	}
}

// Omitting the flag must remain a no-op rather than an error, so the command
// stays usable by hand and in CI without a textfile collector.
func TestEvidenceDoctorWithoutTextfileFlagWritesNothing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeDoctorEntries(t, dir, "evidence-proxy-0.jsonl", doctorEntryPlan{
		{session: "proxy", seq: 0, prev: recorder.GenesisHash},
	})

	cmd := Cmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"doctor", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("clean corpus without the flag failed: %v", err)
	}
}

// seedTruncatingCorpus writes more evidence files than the doctor will read,
// which is the only way a scan becomes inconclusive.
func seedTruncatingCorpus(t *testing.T, dir string) {
	t.Helper()
	for i := range maxEvidenceDoctorFiles + 1 {
		name := filepath.Join(dir, fmt.Sprintf("evidence-proxy-%d.jsonl", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatalf("seed evidence file %d: %v", i, err)
		}
	}
}
