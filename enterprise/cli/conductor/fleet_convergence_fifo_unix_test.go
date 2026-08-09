//go:build enterprise && unix && !aix && !js && !wasip1

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadReceiptProducerInventory_RejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt-producers.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readReceiptProducerInventory(path)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("read FIFO error = %v, want regular-file refusal", err)
		}
	case <-time.After(500 * time.Millisecond):
		if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { // #nosec G304 -- test FIFO under t.TempDir
			_ = writer.Close()
		}
		t.Fatal("readReceiptProducerInventory blocked on FIFO")
	}
}
