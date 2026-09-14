// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func newNotifySocket(t *testing.T) <-chan string {
	t.Helper()
	path := filepath.Join(shortSocketDir(t), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	messages := make(chan string, 8)
	go func() {
		for {
			buf := make([]byte, 1024)
			n, _, readErr := listener.ReadFromUnix(buf)
			if readErr != nil {
				return
			}
			messages <- string(buf[:n])
		}
	}()
	return messages
}

// shortSocketDir returns a directory whose unix socket paths stay under the
// kernel's sun_path limit (108 bytes including the NUL). t.TempDir honors
// TMPDIR, and a deep TMPDIR (CI runners, the pre-push gate) makes bind fail
// with EINVAL, so fall back to a short directory under /tmp in that case.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	const sunPathBudget = 100
	dir := t.TempDir()
	if len(filepath.Join(dir, "notify.sock")) <= sunPathBudget {
		return dir
	}
	short, err := os.MkdirTemp("/tmp", "plk-sdn-")
	if err != nil {
		t.Fatalf("mkdir short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	return short
}

func receiveNotify(t *testing.T, messages <-chan string) string {
	t.Helper()
	select {
	case message := <-messages:
		return message
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for systemd notification")
		return ""
	}
}

func TestSDNotify(t *testing.T) {
	t.Run("sends datagram", func(t *testing.T) {
		messages := newNotifySocket(t)
		sent, err := sdNotify("READY=1")
		if err != nil || !sent {
			t.Fatalf("sdNotify = %v, %v; want sent without error", sent, err)
		}
		if got := receiveNotify(t, messages); got != "READY=1" {
			t.Fatalf("notification = %q, want READY=1", got)
		}
	})

	t.Run("no socket is a no-op", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", "")
		sent, err := sdNotify("READY=1")
		if err != nil || sent {
			t.Fatalf("sdNotify without socket = %v, %v; want false, nil", sent, err)
		}
	})

	t.Run("unreachable socket is bounded", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
		done := make(chan error, 1)
		go func() {
			_, err := sdNotify("READY=1")
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("sdNotify unreachable socket = nil error")
			}
		case <-time.After(time.Second):
			t.Fatal("sdNotify exceeded its bounded deadline")
		}
	})
}

func TestServerSystemdNotifications(t *testing.T) {
	t.Run("startup sends ready once", func(t *testing.T) {
		messages := newNotifySocket(t)
		s, _ := newTestServer(t, func(opts *ServerOpts) {
			opts.Listen = serverTestEphemeralListen
			opts.ListenChanged = true
		})
		errCh := make(chan error, 1)
		go func() { errCh <- s.Start(context.Background()) }()
		if got := receiveNotify(t, messages); got != "READY=1" {
			t.Fatalf("startup notification = %q, want READY=1", got)
		}
		waitForServerCancel(t, s)
		if err := s.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		if got := receiveNotify(t, messages); got != "STOPPING=1" {
			t.Fatalf("shutdown notification = %q, want STOPPING=1", got)
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Start returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Start did not return after shutdown")
		}
	})

	t.Run("signal reload reports accepted verdict", func(t *testing.T) {
		messages := newNotifySocket(t)
		s, _ := newTestServer(t, nil)
		s.sdStartupNotified.Store(true)
		s.handleConfigReload(config.ReloadEvent{Config: s.proxy.CurrentConfig().Clone(), Trigger: config.ReloadTriggerSignal})
		first := receiveNotify(t, messages)
		second := receiveNotify(t, messages)
		if !strings.HasPrefix(first, "RELOADING=1\nMONOTONIC_USEC=") || !monotonicUsec(first) {
			t.Fatalf("first reload notification = %q, want monotonic RELOADING", first)
		}
		if second != "READY=1\nSTATUS=config reload applied" {
			t.Fatalf("completion notification = %q", second)
		}
	})

	t.Run("signal reload reports rejection and preserves policy", func(t *testing.T) {
		messages := newNotifySocket(t)
		s, _ := newTestServer(t, func(opts *ServerOpts) {
			opts.Mode = config.ModeStrict
			opts.ModeChanged = true
		})
		s.sdStartupNotified.Store(true)
		old := s.proxy.CurrentConfig()
		candidate := old.Clone()
		candidate.Mode = config.ModeBalanced
		s.handleConfigReload(config.ReloadEvent{Config: candidate, Trigger: config.ReloadTriggerSignal})
		_ = receiveNotify(t, messages)
		if got := receiveNotify(t, messages); !strings.Contains(got, "READY=1\nSTATUS=config reload rejected:") {
			t.Fatalf("rejected completion notification = %q", got)
		}
		if s.proxy.CurrentConfig() != old {
			t.Fatal("rejected reload replaced the active configuration")
		}
	})
}

func TestSDNotifySignalReloadBeforeStartupReadyIsSilent(t *testing.T) {
	messages := newNotifySocket(t)
	s, _ := newTestServer(t, nil)
	s.handleConfigReload(config.ReloadEvent{Config: s.proxy.CurrentConfig().Clone(), Trigger: config.ReloadTriggerSignal})
	select {
	case message := <-messages:
		t.Fatalf("pre-readiness SIGHUP notified systemd: %q", message)
	default:
	}
}

func monotonicUsec(message string) bool {
	parts := strings.Split(message, "=")
	if len(parts) != 3 || parts[2] == "" {
		return false
	}
	for _, r := range parts[2] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func TestSDNotifyFileReloadDoesNotSignalSystemd(t *testing.T) {
	messages := newNotifySocket(t)
	s, _ := newTestServer(t, nil)
	s.handleConfigReload(config.ReloadEvent{Config: s.proxy.CurrentConfig().Clone(), Trigger: config.ReloadTriggerFile})
	select {
	case message := <-messages:
		t.Fatalf("filesystem reload notified systemd: %q", message)
	default:
	}
}
