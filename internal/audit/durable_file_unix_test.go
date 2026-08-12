// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenDurableAuditFileFailurePaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		path func(t *testing.T) string
		want error
	}{
		{
			name: "missing parent",
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing", "audit.jsonl")
			},
			want: fs.ErrNotExist,
		},
		{
			name: "directory instead of file",
			path: func(t *testing.T) string {
				return t.TempDir()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, created, err := openDurableAuditFile(tc.path(t))
			if file != nil {
				_ = file.Close()
				t.Fatal("openDurableAuditFile returned a file for an unusable path")
			}
			if created {
				t.Fatal("openDurableAuditFile reported an unusable path as created")
			}
			if err == nil {
				t.Fatal("openDurableAuditFile error = nil, want failure")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("openDurableAuditFile error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewDurableFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		logger, err := NewDurableFile("json", path, false, false)
		if logger != nil {
			logger.Close()
		}
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("NewDurableFile accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("NewDurableFile blocked on FIFO without a reader")
	}
}
