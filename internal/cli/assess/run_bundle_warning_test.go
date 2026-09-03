// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/rules"
)

// TestAssessRun_PrintsUnverifiableBundleVersionWarning proves the assessment
// run reports an unprovable min_pipelock gate on stderr, the operator's
// channel, rather than swallowing it or writing it into the evidence set.
func TestAssessRun_PrintsUnverifiableBundleVersionWarning(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	bundleYAML := []byte(`format_version: 1
name: warn-bundle
version: "2026.03.1"
author: Test Author
description: A bundle that declares a minimum version
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: warn-rule-one
    type: dlp
    status: stable
    name: Warn Rule
    description: Detects test patterns
    severity: high
    confidence: high
    pattern:
      regex: "warn-secret-[a-z]+"
`)
	bundleDir := filepath.Join(dataHome, "pipelock", "rules", "warn-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundleYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundleYAML)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "local:/tmp/warn-rules",
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Unsigned:         true,
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatal(err)
	}

	runDir, _ := initTestRun(t)

	// The verify-install step writes its warning to the process stderr because
	// it runs below any command writer; capture it through a pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	captured := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		captured <- string(b)
	}()
	runErr := runAssessRun(runDir, false, nil)
	os.Stderr = origStderr
	_ = w.Close()
	stderr := <-captured
	_ = r.Close()

	if runErr != nil {
		t.Fatalf("runAssessRun: %v\nstderr:\n%s", runErr, stderr)
	}
	if !strings.Contains(stderr, "loaded although min_pipelock") {
		t.Fatalf("assess run did not print the unprovable-version warning to stderr:\n%s", stderr)
	}
	evidence, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "evidence", "verify-install.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence), "loaded although min_pipelock") {
		t.Fatal("the bundle warning entered the evidence set")
	}
}
