// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestIsEvidenceUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"changed during read", fmt.Errorf("walk: %w", ErrEvidenceChanged), true},
		{"permission denied", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: os.ErrPermission}, true},
		{"I/O error", &fs.PathError{Op: "read", Path: "evidence-a-0.jsonl", Err: syscall.EIO}, true},
		{"bare errno", fmt.Errorf("sync: %w", syscall.EIO), true},
		{"missing file is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: os.ErrNotExist}, false},
		{"symlink refused by no-follow open is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: syscall.ELOOP}, false},
		{"path component not a directory is a finding", &fs.PathError{Op: "open", Path: "evidence-a-0.jsonl", Err: syscall.ENOTDIR}, false},
		{"directory where a file belongs is a finding", &fs.PathError{Op: "read", Path: "evidence-a-0.jsonl", Err: syscall.EISDIR}, false},
		{"refused evidence is a finding", fmt.Errorf("%w: evidence file is symlinked", ErrEvidenceRefused), false},
		{"refused evidence wrapping permission stays a finding", fmt.Errorf("%w: %w", ErrEvidenceRefused, os.ErrPermission), false},
		{"malformed content is a finding", errors.New("entry 3: invalid character"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEvidenceUnavailable(tc.err); got != tc.want {
				t.Fatalf("IsEvidenceUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
