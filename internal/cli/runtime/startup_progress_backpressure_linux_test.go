// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestStartupProgressDatagramsBoundedByBudget(t *testing.T) {
	messages := newNotifySocket(t)
	start := time.Now()
	p := startupProgress{last: start, stderr: &syncBuffer{}}
	// Drive more events than the kernel queue can contain in one interval.
	queue := notifyQueueLength(t)
	for i := range queue * 2 {
		now := start.Add(time.Duration(i) * startupProgressInterval / time.Duration(queue*2))
		if err := p.reportAt(verification.Progress{Records: 1}, now); err != nil {
			t.Fatal(err)
		}
		p.sendAt(now)
	}
	if got := receiveNotify(t, messages); !strings.HasPrefix(got, "EXTEND_TIMEOUT_USEC=") {
		t.Fatal(got)
	}
	sdNotifyOrLog(&syncBuffer{}, "READY=1")
	if got := receiveNotify(t, messages); got != "READY=1" {
		t.Fatalf("event count amplified notifications: %s", got)
	}
	// A timer without work must neither extend nor refresh the last progress.
	last := p.last
	p.sendAt(last.Add(cliutil.ServiceStartTimeout))
	if !p.expired || p.last != last {
		t.Fatal("timer manufactured progress")
	}
	_ = p.reportAt(verification.Progress{Records: 1}, last.Add(cliutil.ServiceStartTimeout))
	if !p.expired {
		t.Fatal("later progress revived eligibility")
	}
}

func notifyQueueLength(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/net/unix/max_dgram_qlen")
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || n <= 0 {
		t.Fatalf("unix datagram queue: %q %v", raw, err)
	}
	return n
}

func TestStartupVerificationNotifyBackpressure(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(fmt.Sprint(stalled), func(t *testing.T) {
			t.Setenv("NOTIFY_SOCKET", "")
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "receipt.key")
			_, key, err := signing.GenerateKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			if err = signing.SavePrivateKey(key, keyPath); err != nil {
				t.Fatal(err)
			}
			path := writeServerTestConfig(t, fmt.Sprintf("mode: balanced\nflight_recorder:\n  enabled: true\n  require_receipts: true\n  receipt_chains: 2\n  dir: %q\n  signing_key_path: %q\n", dir, keyPath))
			opts := ServerOpts{ConfigFile: path, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}}
			first, err := NewServer(opts)
			if err != nil {
				t.Fatal(err)
			}
			queue := notifyQueueLength(t)
			for range queue * 2 {
				set := first.receiptShardSet
				if err = set.EmitDurable(set.Admit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Transport: "fetch", Target: "https://api.vendor.example/data"})); err != nil {
					t.Fatal(err)
				}
			}
			first.sealTranscriptRoot()
			first.cleanup()
			socket := filepath.Join(shortSocketDir(t), "notify.sock")
			listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			t.Setenv("NOTIFY_SOCKET", socket)
			if stalled {
				// Fill the real queue and leave it unread through construction, beyond
				// sdNotify's existing write deadline. The kernel, not a fake error, refuses.
				for {
					if _, err = sdNotify("occupied"); err != nil {
						break
					}
				}
			}
			var mu sync.Mutex
			records := uint64(0)
			opts.StartupVerification = verification.Options{Progress: func(event verification.Progress) error { mu.Lock(); records += event.Records; mu.Unlock(); return nil }}
			done := make(chan struct{})
			drained := make(chan struct{})
			count := 0
			var reader sync.WaitGroup
			if !stalled {
				reader.Go(func() {
					// Drain one datagram per millisecond.
					ticker := time.NewTicker(time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-done:
							return
						case <-ticker.C:
							if err := listener.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
								return
							}
							buf := make([]byte, 1024)
							n, _, err := listener.ReadFromUnix(buf)
							if err == nil && string(buf[:n]) == "barrier" {
								close(drained)
								return
							}
							if err == nil && strings.HasPrefix(string(buf[:n]), "EXTEND_TIMEOUT_USEC=") {
								count++
							}
						}
					}
				})
			}
			start := time.Now()
			next, err := NewServer(opts)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("notification backpressure failed verification: %v", err)
			}
			defer next.cleanup()
			if !stalled {
				if _, err = sdNotify("barrier"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-drained:
				case <-time.After(testwait.Deadline(time.Second)):
					t.Fatal("slow reader did not drain notification barrier")
				}
			}
			close(done)
			reader.Wait()
			// #nosec G115 -- notifyQueueLength validates a positive int, representable as uint64.
			if records <= uint64(queue) {
				t.Fatalf("fixture lacked progress pressure: %d <= %d", records, queue)
			}
			failures := strings.Count(opts.Stderr.(*syncBuffer).String(), "startup extensions disabled")
			if stalled {
				if failures != 1 {
					t.Fatalf("send failure not reported exactly once: %d stderr=%s", failures, opts.Stderr.(*syncBuffer).String())
				}
			} else {
				bound := 1 + int(elapsed/startupProgressInterval)
				if count < 1 || count > bound || failures != 0 {
					t.Fatalf("datagrams=%d bound=%d failures=%d", count, bound, failures)
				}
			}
			opening, _ := next.receiptShardSet.Opening()
			if _, err = os.Stat(filepath.Join(dir, "receipt-group-"+opening.GroupID+"-transition.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
