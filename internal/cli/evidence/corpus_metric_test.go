// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The textfile IS the consumer contract for the corpus alert, so its rendered
// content matters as much as the exit code. A metric that writes the wrong
// gauge name is the same failure as no metric at all.
func TestWriteEvidenceCorpusMetricRendersBothGauges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		healthy   bool
		wantValue string
	}{
		{name: "healthy corpus", healthy: true, wantValue: "pipelock_evidence_corpus_integrity_ok 1"},
		{name: "damaged corpus", healthy: false, wantValue: "pipelock_evidence_corpus_integrity_ok 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// A nested directory proves the writer creates its own parents.
			path := filepath.Join(t.TempDir(), "textfile", "pipelock_evidence_corpus.prom")
			before := time.Now().Unix()
			if err := writeEvidenceCorpusMetric(path, tt.healthy); err != nil {
				t.Fatalf("writeEvidenceCorpusMetric: %v", err)
			}

			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("read metric file: %v", err)
			}
			body := string(raw)
			for _, want := range []string{
				"# TYPE pipelock_evidence_corpus_integrity_ok gauge",
				tt.wantValue,
				"# TYPE pipelock_evidence_corpus_last_audit_timestamp_seconds gauge",
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("metric body missing %q:\n%s", want, body)
				}
			}

			// The alert keys staleness off this timestamp, so a wrong or
			// missing value would silently disable the staleness clause.
			stamp := metricValue(t, body, "pipelock_evidence_corpus_last_audit_timestamp_seconds")
			if stamp < before {
				t.Fatalf("audit timestamp = %d, want >= %d", stamp, before)
			}

			// Owner-only, matching the repository's file convention. A
			// collector that cannot read the file produces no series, and the
			// alert's absent() clauses turn that into a firing alert rather
			// than a silent gap, so a restrictive mode stays observable.
			//
			// POSIX-only: Windows honours just the 0o200 write bit from a Go
			// file mode, so asserting the full permission set there would fail
			// on a correct implementation.
			if runtime.GOOS != "windows" {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("stat metric file: %v", err)
				}
				if perm := info.Mode().Perm(); perm != 0o600 {
					t.Fatalf("metric file mode = %04o, want 0600", perm)
				}
			}
		})
	}
}

// A rerun must replace the previous reading rather than append to it, or a
// stale healthy sample would sit alongside a fresh damaged one.
func TestWriteEvidenceCorpusMetricReplacesPreviousReading(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "pipelock_evidence_corpus.prom")
	if err := writeEvidenceCorpusMetric(path, true); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeEvidenceCorpusMetric(path, false); err != nil {
		t.Fatalf("second write: %v", err)
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read metric file: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, "pipelock_evidence_corpus_integrity_ok 1") {
		t.Fatalf("stale healthy sample survived the rerun:\n%s", body)
	}
	// Count SAMPLE lines only. The metric name also appears in its HELP and
	// TYPE lines, so a plain substring count would never be 1.
	samples := 0
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(line, "pipelock_evidence_corpus_integrity_ok ") {
			samples++
		}
	}
	if samples != 1 {
		t.Fatalf("gauge sampled %d times, want exactly 1:\n%s", samples, body)
	}
}

// An unwritable destination must surface an error rather than be swallowed,
// because a silently unwritten metric makes the alert fire absent() forever
// with no explanation in the unit's output.
func TestWriteEvidenceCorpusMetricReportsUnwritableDestination(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	err := writeEvidenceCorpusMetric(filepath.Join(blocker, "pipelock_evidence_corpus.prom"), true)
	if err == nil {
		t.Fatal("writing under a regular file was allowed")
	}
	if !strings.Contains(err.Error(), "Prometheus textfile") {
		t.Fatalf("error = %v, want it to name the Prometheus textfile", err)
	}
}

func metricValue(t *testing.T, body, name string) int64 {
	t.Helper()
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, name+" ")), 10, 64)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return value
	}
	t.Fatalf("metric %s not present in:\n%s", name, body)
	return 0
}
