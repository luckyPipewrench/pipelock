//go:build !windows

package cli

import (
	"bytes"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// syncBuffer is a thread-safe bytes.Buffer for capturing goroutine output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) contains(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Contains(b.buf.Bytes(), []byte(s))
}

func (b *syncBuffer) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func TestRegisterKillSwitchSignal(t *testing.T) {
	cfg := config.Defaults()
	ks := killswitch.New(cfg)
	buf := &syncBuffer{}
	cmd := &cobra.Command{}
	cmd.SetErr(buf)

	cleanup := registerKillSwitchSignal(ks, cmd)

	// Send SIGUSR1 to toggle kill switch ON.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send SIGUSR1: %v", err)
	}

	// Wait for the goroutine to process the signal.
	time.Sleep(200 * time.Millisecond)

	if !buf.contains("ACTIVATED") {
		t.Error("expected ACTIVATED message after first SIGUSR1")
	}

	// Send SIGUSR1 again to toggle OFF.
	buf.reset()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("failed to send second SIGUSR1: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if !buf.contains("DEACTIVATED") {
		t.Error("expected DEACTIVATED message after second SIGUSR1")
	}

	// Cleanup stops signal handling and closes the channel.
	cleanup()
}

func TestReloadSignalHint(t *testing.T) {
	hint := reloadSignalHint()
	if hint != ", SIGHUP to reload" {
		t.Errorf("unexpected hint: %s", hint)
	}
}
