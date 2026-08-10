// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestTrustedDiffGeneratorLimitMatchesScanner pins the CI diff generator's
// default size limit to MaxDiffBytes.
//
// The two are enforced in different languages by different processes, so they
// can only be held together by a check. Drift is silent and wrong in both
// directions: a generator limit BELOW the scanner's refuses to produce diffs the
// scanner would have accepted, turning an ordinary large pull request into a
// failed gate, while one ABOVE it produces input the scanner then rejects, which
// reads to an author as a scanner failure rather than a size limit.
//
// This is a parity test rather than a shared constant because the generator is a
// shell script the workflow runs from a trusted worktree; there is no build step
// in which a Go constant could reach it.
func TestTrustedDiffGeneratorLimitMatchesScanner(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "scripts", "generate-trusted-diff.sh")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read generator script: %v", err)
	}

	m := regexp.MustCompile(`max_bytes=\$\{4:-(\d+)\}`).FindSubmatch(data)
	if m == nil {
		t.Fatal("could not find the generator's default max_bytes; if the script changed shape, update this test rather than deleting it")
	}

	got, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse generator default: %v", err)
	}

	if got != MaxDiffBytes {
		t.Fatalf("generator default = %d bytes, MaxDiffBytes = %d; the CI diff generator and the scanner must accept the same maximum", got, MaxDiffBytes)
	}
}
