// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/testwait"

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
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("timed out waiting for systemd notification")
		return ""
	}
}

// TestSDNotifyErrorPaths covers the failure branches of the notifier. Every one
// of them must report the error and leave the proxy serving: a systemd socket
// that cannot be reached is an availability concern for the start job, never a
// reason to stop mediating traffic.
func TestSDNotifyErrorPaths(t *testing.T) {
	t.Run("dial failure is reported", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", filepath.Join(shortSocketDir(t), "absent.sock"))
		sent, err := sdNotify("READY=1")
		if sent || err == nil {
			t.Fatalf("sdNotify to an absent socket = %v, %v; want a reported failure", sent, err)
		}
		if !strings.Contains(err.Error(), "dial NOTIFY_SOCKET") {
			t.Fatalf("error = %v, want the dial stage named", err)
		}
	})

	t.Run("failure is logged and swallowed by the or-log wrapper", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", filepath.Join(shortSocketDir(t), "absent.sock"))
		var stderr bytes.Buffer
		sdNotifyOrLog(&stderr, "READY=1")
		if !strings.Contains(stderr.String(), "systemd notification failed") {
			t.Fatalf("stderr = %q, want the failure reported", stderr.String())
		}
	})

	t.Run("reloading envelope carries a monotonic timestamp", func(t *testing.T) {
		messages := newNotifySocket(t)
		sdNotifyReloading(io.Discard)
		got := receiveNotify(t, messages)
		if !strings.HasPrefix(got, "RELOADING=1\nMONOTONIC_USEC=") {
			t.Fatalf("reloading notification = %q, want RELOADING with MONOTONIC_USEC", got)
		}
		value := strings.TrimPrefix(got, "RELOADING=1\nMONOTONIC_USEC=")
		if value == "" {
			t.Fatalf("reloading notification carries no timestamp: %q", got)
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				t.Fatalf("monotonic timestamp %q is not an integer", value)
			}
		}
	})

	t.Run("rejected reload reports its reason without the rejected prefix", func(t *testing.T) {
		messages := newNotifySocket(t)
		sdNotifyReloadComplete(io.Discard, errors.New("rejected: security downgrade from strict\nsecond line"))
		got := receiveNotify(t, messages)
		if got != "READY=1\nSTATUS=config reload rejected: security downgrade from strict" {
			t.Fatalf("rejected reload notification = %q", got)
		}
	})
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
		case <-time.After(testwait.Deadline(time.Second)):
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
		case <-time.After(testwait.Deadline(5 * time.Second)):
			t.Fatal("Start did not return after shutdown")
		}
	})

	t.Run("signal reload reports accepted verdict", func(t *testing.T) {
		messages := newNotifySocket(t)
		s, _ := newTestServer(t, nil)
		s.markStartupNotified()
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
		s.markStartupNotified()
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

// TestSDNotifyReloadEventErrorBypassesReload covers the branch where the event
// already carries a load failure. The configuration never parsed, so there is
// nothing to apply: the handler must skip Server.Reload entirely, leave the
// running configuration alone, and still report the rejection so the reload job
// completes with a verdict instead of timing out.
func TestSDNotifyReloadEventErrorBypassesReload(t *testing.T) {
	messages := newNotifySocket(t)
	s, _ := newTestServer(t, nil)
	s.markStartupNotified()
	before := s.proxy.CurrentConfig()

	s.handleConfigReload(config.ReloadEvent{Err: errors.New("rejected: invalid config reload: bad yaml"), Trigger: config.ReloadTriggerSignal})

	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "RELOADING=1") {
		t.Fatalf("first notification = %q, want the reloading envelope", got)
	}
	got := receiveNotify(t, messages)
	if !strings.HasPrefix(got, "READY=1") || !strings.Contains(got, "STATUS=config reload rejected: invalid config reload: bad yaml") {
		t.Fatalf("completion = %q, want a rejected verdict", got)
	}
	if s.proxy.CurrentConfig() != before {
		t.Fatal("a reload event carrying a load failure replaced the running configuration")
	}
}

// TestSDNotifyStatusReasonIsBoundedAndClean covers the status text that rides
// in the completion datagram. It comes from configuration the operator
// controls, so it is unbounded at the source, and READY travels in the same
// datagram: an oversized or control-character-laden status would cost the
// completion systemd is waiting on.
func TestSDNotifyStatusReasonIsBoundedAndClean(t *testing.T) {
	long := errors.New("rejected: " + strings.Repeat("configuration detail ", 200))
	got := sdNotifyStatusReason(long)
	if len(got) > sdNotifyStatusMaxBytes+3 {
		t.Fatalf("status reason is %d bytes, want it bounded near %d", len(got), sdNotifyStatusMaxBytes)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("a truncated reason does not say so: %q", got)
	}

	messy := errors.New("rejected: bad\x00value\x07here\nsecond line")
	got = sdNotifyStatusReason(messy)
	if strings.ContainsAny(got, "\x00\x07\n\r") {
		t.Fatalf("status reason kept a control character: %q", got)
	}
	if got != "bad value here" {
		t.Fatalf("status reason = %q, want the first line with controls replaced", got)
	}

	// Above C0. A byte-range check that keeps everything at or above 0x20 lets
	// these through even though they are controls: U+009B introduces a C1
	// escape sequence and U+0085 is NEL, and either can steer a terminal
	// reading systemd status or an audit log.
	exotic := errors.New("rejected: bad\u009bvalue\u0085here\u2028and\u00a0more")
	got = sdNotifyStatusReason(exotic)
	if strings.ContainsFunc(got, unicode.IsControl) {
		t.Fatalf("status reason kept a Unicode control character: %q", got)
	}
	if got != "bad value here and more" {
		t.Fatalf("status reason = %q, want every non-printable rune replaced by a space", got)
	}
}

// TestSDNotifyReloadCompleteAlwaysDeliversReady pins the property the retry
// exists for: whatever happens to the status, the reload job gets its
// completion, because systemd blocks on READY and nothing else ends the wait.
func TestSDNotifyReloadCompleteAlwaysDeliversReady(t *testing.T) {
	messages := newNotifySocket(t)
	sdNotifyReloadComplete(io.Discard, errors.New("rejected: "+strings.Repeat("x", 4000)))
	got := receiveNotify(t, messages)
	if !strings.HasPrefix(got, "READY=1") {
		t.Fatalf("completion notification = %q, want it to lead with READY", got)
	}
}

// TestStartupReadinessGate covers the gate the reload consumer waits on. It
// has to answer "not yet" before readiness, hand out a channel that closes when
// readiness is published, and tolerate a second publish: the shutdown path and
// the readiness path can both reach it, and a plain close would panic.
func TestStartupReadinessGate(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if s.startupNotifiedAlready() {
		t.Fatal("gate reported readiness before it was published")
	}
	select {
	case <-s.startupNotified():
		t.Fatal("readiness channel was already closed")
	default:
	}

	s.markStartupNotified()
	if !s.startupNotifiedAlready() {
		t.Fatal("gate did not report readiness after it was published")
	}
	select {
	case <-s.startupNotified():
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("readiness channel did not close")
	}

	s.markStartupNotified()
	if !s.startupNotifiedAlready() {
		t.Fatal("a second publish disturbed the gate")
	}
}

func TestSDNotifySignalReloadBeforeStartupReadyIsSilent(t *testing.T) {
	messages := newNotifySocket(t)
	s, _ := newTestServer(t, nil)
	s.handleConfigReload(config.ReloadEvent{Config: s.proxy.CurrentConfig().Clone(), Trigger: config.ReloadTriggerSignal})
	// A bounded window, not an immediate default: the socket reader forwards on
	// another goroutine, so checking the channel straight away can miss a
	// notification that is in flight and report silence that never happened.
	select {
	case message := <-messages:
		t.Fatalf("pre-readiness SIGHUP notified systemd: %q", message)
	case <-time.After(250 * time.Millisecond):
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
	// Bounded, for the same reason as the pre-readiness case above: the socket
	// reader forwards on another goroutine.
	select {
	case message := <-messages:
		t.Fatalf("filesystem reload notified systemd: %q", message)
	case <-time.After(250 * time.Millisecond):
	}
}

// TestConsumeReloadsAbortsWhenStartupNeverSettles covers the two ways the
// readiness gate releases without readiness ever being published. Neither may
// apply the queued configuration: it was queued before a start that failed or
// was cancelled, so applying it would put a configuration into a server that
// is on its way down.
func TestConsumeReloadsAbortsWhenStartupNeverSettles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		abort func(cancel context.CancelFunc, settled chan struct{})
	}{
		{"context cancelled", func(cancel context.CancelFunc, _ chan struct{}) { cancel() }},
		{"startup settled without readiness", func(_ context.CancelFunc, settled chan struct{}) { close(settled) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t, nil)
			before := s.proxy.CurrentConfig()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			settled := make(chan struct{})

			events := make(chan config.ReloadEvent, 1)
			events <- config.ReloadEvent{Config: before.Clone(), Trigger: config.ReloadTriggerSignal}

			done := make(chan struct{})
			go func() {
				defer close(done)
				s.consumeReloads(ctx, events, settled)
			}()

			tc.abort(cancel, settled)
			select {
			case <-done:
			case <-time.After(testwait.Deadline(5 * time.Second)):
				t.Fatal("the reload consumer did not stop when startup never settled")
			}
			if s.proxy.CurrentConfig() != before {
				t.Fatal("a configuration queued before an aborted start was applied anyway")
			}
		})
	}
}

// TestSDNotifyReloadCompleteRetriesReadyAlone covers the send-failure path: the
// combined datagram is what carries READY, so if it cannot be written the
// completion is retried on its own rather than left for systemd to wait on.
func TestSDNotifyReloadCompleteRetriesReadyAlone(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(shortSocketDir(t), "absent.sock"))
	var stderr bytes.Buffer
	sdNotifyReloadComplete(&stderr, errors.New("rejected: nothing will reach the socket"))
	if got := strings.Count(stderr.String(), "systemd notification failed"); got != 2 {
		t.Fatalf("stderr reported %d failures, want the combined send and the bare READY retry:\n%s", got, stderr.String())
	}
}

// TestReloadWithoutSystemdIsUnchangedAndSilent covers every init system that
// is not systemd -- s6, runit, OpenRC, sysvinit, and a plain foreground
// process. All of them leave NOTIFY_SOCKET unset.
//
// The property is that startup readiness is published unconditionally rather
// than only when a notify socket exists. The gate that holds a SIGHUP reload
// waits on exactly that signal, so a readiness publication made conditional on
// systemd would leave the gate shut forever on these hosts and silently stop
// honouring SIGHUP everywhere except systemd. That is why this drives Start
// rather than publishing readiness by hand: the call under test is the one
// inside Start, and a test that marks readiness itself would pass either way.
//
// The notify calls themselves also stay quiet here: with no socket they are
// no-ops with no error, so the host is never told a protocol it does not speak
// has failed.
func TestReloadWithoutSystemdIsUnchangedAndSilent(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	var stderr bytes.Buffer
	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.Listen = serverTestEphemeralListen
		opts.ListenChanged = true
	})
	s.opts.Stderr = &stderr

	errCh := make(chan error, 1)
	go func() { errCh <- s.Start(context.Background()) }()

	deadline := time.After(testwait.Deadline(10 * time.Second))
	for !s.startupNotifiedAlready() {
		select {
		case <-deadline:
			t.Fatal("startup readiness was never published on a host with no systemd, so the reload gate would never open")
		case err := <-errCh:
			t.Fatalf("Start returned early: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Readiness alone only proves the gate can open. Drive a signal-triggered
	// reload through the consumer and require it to finish and take effect, so
	// a gate that opens but never releases the event still fails here.
	next := s.proxy.CurrentConfig().Clone()
	next.Mode = config.ModeAudit
	if next.Mode == s.proxy.CurrentConfig().Mode {
		next.Mode = config.ModeStrict
	}
	events := make(chan config.ReloadEvent, 1)
	events <- config.ReloadEvent{Config: next, Trigger: config.ReloadTriggerSignal}
	close(events)

	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		s.consumeReloads(context.Background(), events, make(chan struct{}))
	}()
	select {
	case <-reloadDone:
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("a SIGHUP-triggered reload never completed on a host with no systemd")
	}
	if got := s.proxy.CurrentConfig().Mode; got != next.Mode {
		t.Fatalf("mode = %q, want %q: the reload completed without applying its configuration", got, next.Mode)
	}

	waitForServerCancel(t, s)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(testwait.Deadline(10 * time.Second)):
		t.Fatal("Start did not return after shutdown")
	}

	// Ordinary startup and reload warnings are expected and are not what this
	// asserts. What must never appear is a complaint about the systemd
	// protocol, which this host does not speak.
	if strings.Contains(stderr.String(), "systemd notification failed") {
		t.Fatalf("a non-systemd init was told the systemd protocol failed: %q", stderr.String())
	}
}
