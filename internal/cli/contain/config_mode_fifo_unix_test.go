// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// A runtime.GOOS skip does not stop COMPILATION: syscall.Mkfifo does not exist
// on Windows, so keeping this case in the shared test file broke the Windows
// build of the package even though the test would have skipped there. The
// build tag is the only thing that actually excludes it.

package contain

import (
	"bytes"
	"context"
	"syscall"
	"testing"
	"time"
)

// A FIFO at the managed path must be refused PROMPTLY. O_NOFOLLOW refuses a
// symlink and says nothing about a FIFO, and opening one for reading blocks
// until a writer appears, before the regular-file check can run. The account
// that owns the config directory could therefore hang a privileged install
// indefinitely, so this asserts the call returns rather than only that it
// errors.
func TestRepairManagedConfigMode_RefusesFifoWithoutBlocking(t *testing.T) {
	var out bytes.Buffer
	env := &installEnv{configDir: t.TempDir(), out: &out, repairLeafMode: setLeafModeNoFollow}
	if err := syscall.Mkfifo(managedPipelockConfigPath(env), 0o600); err != nil {
		t.Skipf("cannot create FIFO here: %v", err)
	}

	type result struct {
		applied bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		applied, err := stepRepairManagedConfigMode().apply(context.Background(), env)
		done <- result{applied, err}
	}()

	select {
	case got := <-done:
		if got.err == nil {
			t.Fatal("a FIFO at the managed config path was accepted")
		}
		if got.applied {
			t.Error("FIFO reported as repaired")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("repair blocked on a FIFO; an unprivileged account can hang a privileged install")
	}
}
