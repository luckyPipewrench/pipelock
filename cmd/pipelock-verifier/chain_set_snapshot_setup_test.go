// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
}
