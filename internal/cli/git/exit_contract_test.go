// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
)

// diffWithSecret returns a well-formed unified diff whose added line carries a
// detectable credential, so scanning succeeds and produces a finding.
//
// The credential is assembled at run time rather than written literally, or
// pipelock's own scan of this repository flags this fixture as a real leak.
func diffWithSecret() string {
	key := strings.Join([]string{"AWS", "SECRET", "ACCESS", "KEY"}, "_")
	value := strings.Repeat("A", 20) + strings.Repeat("b", 20)
	return "diff --git a/config.env b/config.env\n" +
		"--- a/config.env\n" +
		"+++ b/config.env\n" +
		"@@ -0,0 +1 @@\n" +
		"+" + key + "=" + value + "\n"
}

// unwritablePath returns a path that cannot be created, because a regular file
// stands where its parent directory would have to be.
func unwritablePath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	return filepath.Join(blocker, "report.sarif")
}

// runScanDiffArgs runs scan-diff with extra arguments and the given stdin.
func runScanDiffArgs(t *testing.T, diff string, args ...string) error {
	t.Helper()
	stdin, err := os.CreateTemp(t.TempDir(), "scan-diff-stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.WriteString(diff); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close() })

	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	cmd := testRootCmd()
	cmd.SetArgs(append([]string{"git", "scan-diff"}, args...))
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd.Execute()
}

// blockedWriter fails every write, standing in for a closed pipe or a full disk
// on the stream the scan result is delivered to.
type blockedWriter struct{}

func (blockedWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write blocked")
}

// runScanDiffBlockedOutput runs scan-diff with a stream that cannot be written.
func runScanDiffBlockedOutput(t *testing.T, diff string, blockStdout bool, args ...string) error {
	t.Helper()
	stdin, err := os.CreateTemp(t.TempDir(), "scan-diff-stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.WriteString(diff); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close() })

	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	cmd := testRootCmd()
	cmd.SetArgs(append([]string{"git", "scan-diff"}, args...))
	discard := &strings.Builder{}
	if blockStdout {
		cmd.SetOut(blockedWriter{})
		cmd.SetErr(discard)
	} else {
		cmd.SetOut(discard)
		cmd.SetErr(blockedWriter{})
	}
	return cmd.Execute()
}

// A result that never reaches the caller is not a delivered scan. Discarding the
// write error would let a clean scan exit 0 with no output, which a caller
// cannot tell apart from a clean scan it actually received.
func TestScanDiffCmd_UndeliverableResultExitsTwo(t *testing.T) {
	for _, tc := range []struct {
		name        string
		diff        string
		blockStdout bool
		args        []string
	}{
		{
			name:        "json findings that cannot be written",
			diff:        diffWithSecret(),
			blockStdout: true,
			args:        []string{"--json"},
		},
		{
			name:        "empty json result that cannot be written",
			diff:        "",
			blockStdout: true,
			args:        []string{"--json"},
		},
		{
			name: "text findings that cannot be written",
			diff: diffWithSecret(),
			args: []string{"--format", "text"},
		},
		{
			// For empty input the "no diff content" line is the entire result, so
			// losing it is losing the result, not losing a diagnostic.
			name: "empty text result that cannot be written",
			diff: "",
			args: []string{"--format", "text"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runScanDiffBlockedOutput(t, tc.diff, tc.blockStdout, tc.args...)
			if err == nil {
				t.Fatal("expected an error when the result cannot be delivered")
			}
			if !errors.Is(err, ErrScanUnverified) {
				t.Fatalf("undelivered result is not classed unverified: %v", err)
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d (%v)", got, cliutil.ExitConfig, err)
			}
		})
	}
}

// Exit status 1 means findings are present. Every other failure has to leave
// through status 2, or a caller reading the status alone is told a leak was
// found in a diff that was never successfully scanned.
func TestScanDiffCmd_EveryUnverifiableFailureExitsTwo(t *testing.T) {
	oversized := strings.Repeat("a", gitprotect.MaxDiffBytes+1)

	tests := []struct {
		name string
		diff string
		args []string
	}{
		{
			name: "diff larger than the scanner will read",
			diff: oversized,
		},
		{
			name: "unsupported output format",
			diff: "garbage\n",
			args: []string{"--format", "yaml"},
		},
		{
			name: "config that cannot be loaded",
			diff: "garbage\n",
			args: []string{"--config", filepath.Join(t.TempDir(), "absent.yaml")},
		},
		{
			// A SARIF report that cannot be written leaves the caller with no
			// result at all, which is not a clean scan.
			name: "sarif report that cannot be written",
			diff: diffWithSecret(),
			args: []string{"--format", "sarif", "-o", unwritablePath(t)},
		},
		{
			// The same write failure on the empty-diff path, which returns before
			// any scanning happens and has its own SARIF branch.
			name: "sarif report for an empty diff that cannot be written",
			diff: "",
			args: []string{"--format", "sarif", "-o", unwritablePath(t)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runScanDiffArgs(t, tc.diff, tc.args...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrScanUnverified) {
				t.Fatalf("error is not classed unverifiable: %v", err)
			}
			if errors.Is(err, ErrSecretsFound) {
				t.Fatalf("unverifiable input reported as a secret finding: %v", err)
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d (%v)", got, cliutil.ExitConfig, err)
			}
		})
	}
}

// A diff that cannot be read at all is the clearest unverifiable case: nothing
// was scanned, so reporting it as a finding would be inventing one.
func TestScanDiffCmd_UnreadableStdinExitsTwo(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "scan-diff-closed-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	oldStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	cmd := testRootCmd()
	cmd.SetArgs([]string{"git", "scan-diff"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected an error reading a closed stdin")
	}
	if !errors.Is(err, ErrScanUnverified) {
		t.Fatalf("error is not classed unverifiable: %v", err)
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("unreadable stdin exit code = %d, want %d", got, cliutil.ExitConfig)
	}
}

// The oversized case is the one a caller is most likely to hit by accident, and
// it must name the size limit rather than fail anonymously.
func TestScanDiffCmd_OversizedDiffNamesTheLimit(t *testing.T) {
	err := runScanDiffArgs(t, strings.Repeat("a", gitprotect.MaxDiffBytes+1))
	if err == nil {
		t.Fatal("expected an error for an oversized diff")
	}
	if !errors.Is(err, gitprotect.ErrDiffTooLarge) {
		t.Fatalf("expected ErrDiffTooLarge, got: %v", err)
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("oversized diff exit code = %d, want %d", got, cliutil.ExitConfig)
	}
}
