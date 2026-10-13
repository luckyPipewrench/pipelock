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
	if got := receiveNotify(t, messages); got != want {
		t.Fatalf("first extension=%q", got)
	}
	now = now.Add(cliutil.ServiceStartTimeout - time.Nanosecond)
	if err := p.reportAt(event, now); err != nil {
		t.Fatal(err)
	}
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
				if err == nil || !strings.Contains(stderr.String(), "systemd notification failed") {
					t.Fatalf("error=%v stderr=%q", err, stderr.String())
				}
			} else if err != nil || stderr.Len() != 0 {
				t.Fatalf("absent socket error=%v stderr=%q", err, stderr.String())
			}
		})
	}
}
