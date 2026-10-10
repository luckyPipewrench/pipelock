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
		{"malformed content is a finding", errors.New("entry 3: invalid character"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEvidenceUnavailable(tc.err); got != tc.want {
				t.Fatalf("IsEvidenceUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
