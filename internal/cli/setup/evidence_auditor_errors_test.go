// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every install failure must be reported and named. A partially installed
// auditor that reports success is how the corpus ends up unwatched while the
// operator believes it is watched, which is the defect this feature exists to
// close.
func TestInstallEvidenceCorpusAuditorReportsEachFailure(t *testing.T) {
	sentinel := errors.New("seam failed")

	tests := []struct {
		name        string
		recorderDir string
		arrange     func(t *testing.T)
		wantErr     string
	}{
		{
			name:        "unconfigured recorder directory",
			recorderDir: "   ",
			arrange:     func(*testing.T) {},
			wantErr:     "needs a configured flight_recorder.dir",
		},
		{
			name:        "user config directory unavailable",
			recorderDir: "/var/lib/pipelock/evidence",
			arrange: func(t *testing.T) {
				stub(t, &evidenceAuditorUserConfigDir, func() (string, error) { return "", sentinel })
			},
			wantErr: "determining user config directory",
		},
		{
			name:        "executable path unresolvable",
			recorderDir: "/var/lib/pipelock/evidence",
			arrange: func(t *testing.T) {
				stub(t, &evidenceAuditorUserConfigDir, func() (string, error) { return t.TempDir(), nil })
				stub(t, &evidenceAuditorExecutable, func() (string, error) { return "", sentinel })
			},
			wantErr: "resolving pipelock executable",
		},
		{
			name:        "daemon reload fails",
			recorderDir: "/var/lib/pipelock/evidence",
			arrange: func(t *testing.T) {
				stub(t, &evidenceAuditorUserConfigDir, func() (string, error) { return t.TempDir(), nil })
				stub(t, &evidenceAuditorExecutable, func() (string, error) { return "/usr/bin/pipelock", nil })
				stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
					if op == systemctlDaemonReload {
						return sentinel
					}
					return nil
				})
			},
			wantErr: "reloading evidence corpus auditor unit",
		},
		{
			name:        "timer enable fails",
			recorderDir: "/var/lib/pipelock/evidence",
			arrange: func(t *testing.T) {
				stub(t, &evidenceAuditorUserConfigDir, func() (string, error) { return t.TempDir(), nil })
				stub(t, &evidenceAuditorExecutable, func() (string, error) { return "/usr/bin/pipelock", nil })
				stub(t, &evidenceAuditorSystemctl, func(_ context.Context, op systemctlOp) error {
					if op == systemctlEnableAuditorTimer {
						return sentinel
					}
					return nil
				})
			},
			wantErr: "enabling evidence corpus auditor timer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.arrange(t)

			_, err := installEvidenceCorpusAuditor(t.Context(), tt.recorderDir)
			if err == nil {
				t.Fatal("install reported success despite a failing seam")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// An operator's own file must never be silently replaced, and the refusal has
// to name the path so they can decide what to keep.
func TestWriteManagedEvidenceAuditorFileRefusesUnmanagedContent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), evidenceCorpusAuditorAlert)
	if err := os.WriteFile(path, []byte("groups: [] # hand written\n"), 0o600); err != nil {
		t.Fatalf("seed unmanaged file: %v", err)
	}

	err := writeManagedEvidenceAuditorFile(path, renderEvidenceCorpusAuditorAlert())
	if err == nil {
		t.Fatal("an unmanaged operator file was overwritten")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want it to name %s", err, path)
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(raw), "hand written") {
		t.Fatalf("operator content was modified: %s", raw)
	}
}

// Every write failure must be surfaced and must name the file, because a
// half-installed auditor that reports success is the exact condition this
// feature exists to detect.
func TestWriteManagedEvidenceAuditorFileSurfacesWriteFailures(t *testing.T) {
	t.Parallel()

	t.Run("parent path is a regular file", func(t *testing.T) {
		t.Parallel()

		blocker := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed blocking file: %v", err)
		}

		err := writeManagedEvidenceAuditorFile(filepath.Join(blocker, "child", evidenceCorpusAuditorAlert), "body")
		if err == nil {
			t.Fatal("writing beneath a regular file was allowed")
		}
		if !strings.Contains(err.Error(), "evidence corpus auditor directory") {
			t.Fatalf("error = %v, want it to name the directory step", err)
		}
	})

	t.Run("existing path is a directory", func(t *testing.T) {
		t.Parallel()

		// A directory where the managed file belongs makes both the read and
		// the write fail with something other than not-exist, which is the
		// branch a plain missing-file test never reaches.
		path := filepath.Join(t.TempDir(), evidenceCorpusAuditorAlert)
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("seed directory: %v", err)
		}

		err := writeManagedEvidenceAuditorFile(path, "body")
		if err == nil {
			t.Fatal("a directory in the managed file's place was accepted")
		}
		if !strings.Contains(err.Error(), path) {
			t.Fatalf("error = %v, want it to name %s", err, path)
		}
	})

	t.Run("identical managed content is left alone", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), evidenceCorpusAuditorAlert)
		body := renderEvidenceCorpusAuditorAlert()
		if err := writeManagedEvidenceAuditorFile(path, body); err != nil {
			t.Fatalf("first write: %v", err)
		}
		before, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat after first write: %v", err)
		}
		if err := writeManagedEvidenceAuditorFile(path, body); err != nil {
			t.Fatalf("rerun with identical content: %v", err)
		}
		after, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat after rerun: %v", err)
		}
		if !after.ModTime().Equal(before.ModTime()) {
			t.Fatal("rerun rewrote a file whose content had not changed")
		}
	})
}

// stub replaces a package seam for the duration of one test.
func stub[T any](t *testing.T, target *T, replacement T) {
	t.Helper()
	original := *target
	t.Cleanup(func() { *target = original })
	*target = replacement
}
