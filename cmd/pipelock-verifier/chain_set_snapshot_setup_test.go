// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// A base snapshot that fails before its consumer runs is a listing failure: it
// must stop the chain path, read as an evidence-content error, and print no
// success.
func TestChainSetSnapshotSetupFailureIsListingError(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	location := recorder.EvidenceLocation{Dir: filepath.Join(t.TempDir(), "missing")}
	handled, err := runChainSetIfRuns(&stdout, &stderr, location, chainTrust{}, chainOptions{sessionID: "proxy"})
	if !handled || err == nil {
		t.Fatalf("handled=%t err=%v, want a handled listing failure", handled, err)
	}
	if !strings.Contains(err.Error(), "listing receipt chains") {
		t.Fatalf("err=%v, want the listing wording", err)
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitGeneral {
		t.Fatalf("exit code=%d, want %d", got, cliutil.ExitGeneral)
	}
	if strings.Contains(stdout.String(), "VALID") {
		t.Fatalf("setup failure printed success: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "VERIFICATION INCOMPLETE") || strings.Contains(stderr.String(), "BROKEN") {
		t.Fatalf("text mode must say incomplete, not broken: %q", stderr.String())
	}
}

// In JSON mode a voided snapshot still yields one parseable report, so a
// consumer never reads empty stdout as a verdict.
func TestChainSetSnapshotFailureEmitsJSONReport(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	location := recorder.EvidenceLocation{Dir: filepath.Join(t.TempDir(), "missing")}
	handled, err := runChainSetIfRuns(&stdout, &stderr, location, chainTrust{}, chainOptions{sessionID: "proxy", jsonOutput: true})
	if !handled || err == nil {
		t.Fatalf("handled=%t err=%v, want a handled failure", handled, err)
	}
	var report chainReport
	if decodeErr := json.Unmarshal(stdout.Bytes(), &report); decodeErr != nil {
		t.Fatalf("stdout is not one JSON report: %v (%q)", decodeErr, stdout.String())
	}
	if report.Valid || report.Path != location.Dir || !strings.Contains(report.Error, "listing receipt chains") {
		t.Fatalf("report=%+v, want invalid with the listing reason", report)
	}
}

// An ordinary (non-run) session whose shards share a sequence start is a
// broken chain, and it is reported like any other outcome: a JSON document in
// --json mode and CHAIN BROKEN in text mode, never a bare error.
func TestChainDirOrdinarySessionReadFailureIsReported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-00.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stdout, stderr, code := runRoot(t, "chain", dir, "--dir", "--allow-unpinned", "--json")
	if code != cliutil.ExitGeneral {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, cliutil.ExitGeneral, stdout, stderr)
	}
	var report chainReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("--json printed no report: %v (%q)", err, stdout)
	}
	if report.Valid || !strings.Contains(report.Error, "sequence") {
		t.Fatalf("report=%+v, want invalid naming the ambiguous sequence start", report)
	}
	stdout, stderr, code = runRoot(t, "chain", dir, "--dir", "--allow-unpinned")
	if code != cliutil.ExitGeneral || !strings.Contains(stderr, "CHAIN BROKEN") || strings.Contains(stdout, "VALID") {
		t.Fatalf("text mode must report a broken chain and fail: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
