//go:build enterprise && !windows

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenRegularDashboardFileRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		file, _, err := openRegularDashboardFile(path, "dashboard state")
		if file != nil {
			_ = file.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "non-regular") {
			t.Fatalf("openRegularDashboardFile FIFO error = %v, want non-regular", err)
		}
	case <-time.After(500 * time.Millisecond):
		if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { // #nosec G304 -- test FIFO under t.TempDir
			_ = writer.Close()
		}
		t.Fatal("openRegularDashboardFile blocked on FIFO")
	}
}
