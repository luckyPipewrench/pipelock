// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoldenVectors_PythonVerifier runs the cross-implementation Python
// verifier against the Go-emitted golden vectors. Skipped if python3 is not
// available or required deps are missing — this test is informational on
// developer machines and load-bearing in CI.
func TestGoldenVectors_PythonVerifier(t *testing.T) {
	if testing.Short() {
		t.Skip("python verifier requires python3 + cryptography + jcs deps")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not in PATH")
	}

	ctx := context.Background()

	// Quick dep check: import jcs + cryptography.
	probe := exec.CommandContext(ctx, "python3", "-c", "import jcs, cryptography.hazmat.primitives.asymmetric.ed25519")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("python deps missing (need cryptography + jcs): %v\n%s", err, out)
	}

	repoRoot, err := filepath.Abs(filepath.Join(".."))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	verifier := filepath.Clean(filepath.Join(repoRoot, "..", "testdata", "python_verifier_fixture", "verify.py"))
	goldenDir := filepath.Clean(filepath.Join(repoRoot, "contract", "testdata", "golden"))

	cmd := exec.CommandContext(ctx, "python3", verifier, goldenDir) //nolint:gosec // verifier path is constructed from filepath.Clean'd repo-relative constant
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("python verifier failed with exit %d:\n%s", exitErr.ExitCode(), out)
		}
		t.Fatalf("python verifier exec error: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("all golden vectors verified")) {
		t.Errorf("python verifier did not print success line:\n%s", out)
	}
	// Sanity: every VERIFIERS entry should produce one OK line.
	const expectedOKs = 7
	got := strings.Count(string(out), "OK ")
	if got != expectedOKs {
		t.Errorf("expected %d OK lines, got %d:\n%s", expectedOKs, got, out)
	}
	t.Logf("python verifier output:\n%s", out)
}
