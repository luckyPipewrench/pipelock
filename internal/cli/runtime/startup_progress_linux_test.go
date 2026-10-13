// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestStartupProgressNotifyEligibility(t *testing.T) {
	messages := newNotifySocket(t)
	now := time.Now()
	p := startupProgress{last: now, stderr: io.Discard}
	event := verification.Progress{Bytes: 1}
	want := fmt.Sprintf("EXTEND_TIMEOUT_USEC=%d", cliutil.ServiceStartTimeout/time.Microsecond)
	if err := p.reportAt(event, now); err != nil {
		t.Fatal(err)
	}
	p.sendAt(now)
	if got := receiveNotify(t, messages); got != want {
		t.Fatalf("first extension=%q", got)
	}
	now = now.Add(cliutil.ServiceStartTimeout - time.Nanosecond)
	if err := p.reportAt(event, now); err != nil {
		t.Fatal(err)
	}
	p.sendAt(now)
	if got := receiveNotify(t, messages); got != want {
		t.Fatalf("continued extension=%q", got)
	}
	if err := p.reportAt(event, now.Add(cliutil.ServiceStartTimeout)); err != nil {
		t.Fatal(err)
	}
	if !p.expired {
		t.Fatal("stalled verifier retained eligibility")
	}
	if err := p.reportAt(event, now.Add(cliutil.ServiceStartTimeout+time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	// A completion datagram is a deterministic barrier after all report calls.
	sdNotifyOrLog(io.Discard, "READY=1")
	if got := receiveNotify(t, messages); got != "READY=1" {
		t.Fatalf("stalled verifier extended: %q", got)
	}
}

func TestStartupProgressAbsentSocketAndSendError(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			socket := ""
			if invalid {
				socket = filepath.Join(shortSocketDir(t), "absent.sock")
			}
			t.Setenv("NOTIFY_SOCKET", socket)
			var stderr bytes.Buffer
			p := startupProgress{last: time.Now(), stderr: &stderr}
			err := p.reportAt(verification.Progress{Records: 1}, time.Now())
			if invalid {
				p.sendAt(time.Now())
				_ = p.reportAt(verification.Progress{Records: 1}, time.Now().Add(startupProgressInterval))
				p.sendAt(time.Now().Add(startupProgressInterval))
				if err != nil || !p.expired || strings.Count(stderr.String(), "systemd notification failed") != 1 {
					t.Fatalf("error=%v stderr=%q", err, stderr.String())
				}
			} else if err != nil || stderr.Len() != 0 {
				t.Fatalf("absent socket error=%v stderr=%q", err, stderr.String())
			}
		})
	}
}

func TestStartupProgressRequiresFreshWorkEachInterval(t *testing.T) {
	messages := newNotifySocket(t)
	now := time.Now()
	p := startupProgress{last: now, stderr: io.Discard}
	for i := range 3 {
		if err := p.reportAt(verification.Progress{Records: 1}, now); err != nil {
			t.Fatal(err)
		}
		p.sendAt(now)
		if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
			t.Fatal(got)
		}
		// Further work in the same interval must not amplify sends.
		if i < 2 {
			_ = p.reportAt(verification.Progress{Records: 1}, now.Add(time.Nanosecond))
		}
		p.sendAt(now.Add(time.Nanosecond))
		sdNotifyOrLog(io.Discard, "barrier")
		if got := receiveNotify(t, messages); got != "barrier" {
			t.Fatal(got)
		}
		now = now.Add(startupProgressInterval)
	}
	// An interval without new work does not send, even before the full-budget stall.
	p.sendAt(now)
	sdNotifyOrLog(io.Discard, "barrier")
	if got := receiveNotify(t, messages); got != "barrier" {
		t.Fatalf("no new work: %s", got)
	}
}

func TestStartupProgressResumesAfterQuietInterval(t *testing.T) {
	messages := newNotifySocket(t)
	now := time.Now()
	p := startupProgress{last: now, stderr: io.Discard, wake: make(chan struct{}, 1)}
	event := verification.Progress{Records: 1}
	if err := p.reportAt(event, now); err != nil {
		t.Fatal(err)
	}
	<-p.wake
	p.sendAt(now)
	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
		t.Fatal(got)
	}
	// The empty interval must not extend. Resumed work just before the
	// advertised deadline must wake the sender rather than await that deadline.
	p.sendAt(now.Add(startupProgressInterval))
	resumed := now.Add(cliutil.ServiceStartTimeout - time.Nanosecond)
	if err := p.reportAt(event, resumed); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.wake:
	default:
		t.Fatal("resumed progress did not wake sender before extension deadline")
	}
	p.sendAt(resumed)
	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
		t.Fatal(got)
	}
	sdNotifyOrLog(io.Discard, "barrier")
	if got := receiveNotify(t, messages); got != "barrier" {
		t.Fatal(got)
	}
}

func TestStartupSenderHandlesResumedProgress(t *testing.T) {
	messages := newNotifySocket(t)
	p := startupProgress{last: time.Now(), stderr: io.Discard, wake: make(chan struct{}, 1)}
	stop, joined := make(chan struct{}), make(chan struct{})
	go func() { defer close(joined); p.run(stop) }()
	defer func() { close(stop); <-joined }()
	event := verification.Progress{Records: 1}
	if err := p.reportAt(event, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
		t.Fatal(got)
	}
	// Advance the retained send clock past the existing cadence without waiting
	// for a real interval. The sender's timer has not fired, so only the wake
	// branch can deliver the newly eligible progress notification.
	p.mu.Lock()
	p.sentAt = time.Now().Add(-startupProgressInterval)
	p.mu.Unlock()
	if err := p.reportAt(event, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
		t.Fatal(got)
	}
}
