// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// stubWatcher is a Watcher that drives Findings() from a pre-seeded
// channel. Arm / Start / Close are no-ops sufficient for testing the
// consumer's enforcement decisions in isolation from fsnotify.
type stubWatcher struct {
	ch       chan Finding
	overflow chan Finding
}

func (s *stubWatcher) Arm() error                    { return nil }
func (s *stubWatcher) Start(_ context.Context) error { return nil }
func (s *stubWatcher) Findings() <-chan Finding      { return s.ch }
func (s *stubWatcher) OverflowFindings() <-chan Finding {
	return s.overflow
}
func (s *stubWatcher) DegradedPaths() []DegradedPath { return nil }

func (s *stubWatcher) DegradedPathCount() int { return 0 }
func (s *stubWatcher) Close() error           { return nil }

// makeWatcher seeds a buffered channel with the given findings and closes
// it. The returned Watcher emits each finding once and then terminates,
// so ConsumeFindings exits cleanly after draining.
func makeWatcher(t *testing.T, findings ...Finding) Watcher {
	t.Helper()
	ch := make(chan Finding, len(findings))
	for _, f := range findings {
		ch <- f
	}
	close(ch)
	overflow := make(chan Finding)
	close(overflow)
	return &stubWatcher{ch: ch, overflow: overflow}
}

// newBlockModeConsumerWatcher uses the real watcher event and delivery paths
// so skipped-file tests cannot pass merely because a stub never emits. The
// mock lineage makes the write agent-attributed; only an emitted Finding may
// reach ConsumeFindings and cancel the child context.
func newBlockModeConsumerWatcher(t *testing.T, maxFileBytes int64) (
	dir string,
	watcher *fsWatcher,
	errs <-chan error,
	cancelCount *atomic.Int32,
	blocked <-chan Finding,
	finish func(),
) {
	t.Helper()
	dir = t.TempDir()
	cfg := &config.FileSentry{
		Enabled:      true,
		WatchPaths:   []config.WatchPath{{Path: dir}},
		ScanContent:  ptrBool(true),
		MaxFileBytes: maxFileBytes,
	}
	defaults := config.Defaults()
	defaults.Internal = nil
	defaults.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.MustNew(defaults)
	t.Cleanup(sc.Close)

	errorCh := make(chan error, 4)
	w, err := NewWatcher(cfg, sc, &mockLineage{hasFileOpen: true}, func(err error) {
		select {
		case errorCh <- err:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	watcher, ok := w.(*fsWatcher)
	if !ok {
		t.Fatalf("NewWatcher returned %T, want *fsWatcher", w)
	}
	if err := watcher.Arm(); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	counts := &atomic.Int32{}
	blockCh := make(chan Finding, 1)
	wait := ConsumeFindings(ConsumerOpts{
		Watcher: watcher,
		Action:  config.ActionBlock,
		Cancel:  func() { counts.Add(1) },
		OnBlock: func(f Finding) { blockCh <- f },
	})
	var once sync.Once
	finish = func() {
		once.Do(func() {
			if err := watcher.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
			wait()
		})
	}
	t.Cleanup(finish)
	return dir, watcher, errorCh, counts, blockCh, finish
}

func waitForConsumerWatcherError(t *testing.T, errs <-chan error, want string) {
	t.Helper()
	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("watcher error = %q, want %q", err, want)
		}
	case <-time.After(filesentryPositiveBackstop):
		t.Fatalf("timeout waiting for watcher error containing %q", want)
	}
}

func TestConsumeFindings_BlockMode_SkippedAgentWritesDoNotCancel(t *testing.T) {
	const maxFileBytes = 128
	secret := "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

	t.Run("oversized write", func(t *testing.T) {
		dir, watcher, errs, cancelCount, blocked, finish := newBlockModeConsumerWatcher(t, maxFileBytes)
		path := filepath.Join(dir, "oversized.txt")
		if err := os.WriteFile(path, append([]byte(secret), []byte(strings.Repeat("x", 256))...), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		watcher.handleEvent(context.Background(), fsnotify.Event{Name: path, Op: fsnotify.Write})
		waitForConsumerWatcherError(t, errs, "oversized")
		finish()

		if got := cancelCount.Load(); got != 0 {
			t.Errorf("oversized agent write must not cancel without a Finding, got %d calls", got)
		}
		select {
		case finding := <-blocked:
			t.Errorf("oversized agent write reached OnBlock with %+v", finding)
		default:
		}
	})

	t.Run("open failure", func(t *testing.T) {
		dir, watcher, errs, cancelCount, blocked, finish := newBlockModeConsumerWatcher(t, maxFileBytes)
		path := filepath.Join(dir, "raced-away.txt")
		if err := os.WriteFile(path, []byte("clean content"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		watcher.handleEvent(context.Background(), fsnotify.Event{Name: path, Op: fsnotify.Write})
		waitForPendingTimer(t, watcher, path)
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		waitForConsumerWatcherError(t, errs, "open failed")
		finish()

		if got := cancelCount.Load(); got != 0 {
			t.Errorf("open failure must not cancel without a Finding, got %d calls", got)
		}
		select {
		case finding := <-blocked:
			t.Errorf("open failure reached OnBlock with %+v", finding)
		default:
		}
	})

	t.Run("normal-sized finding cancels", func(t *testing.T) {
		dir, watcher, _, cancelCount, blocked, finish := newBlockModeConsumerWatcher(t, maxFileBytes)
		path := filepath.Join(dir, "detected.txt")
		if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		watcher.handleEvent(context.Background(), fsnotify.Event{Name: path, Op: fsnotify.Write})
		select {
		case finding := <-blocked:
			if finding.Path != path || !finding.IsAgent {
				t.Errorf("OnBlock finding = %+v, want agent finding for %q", finding, path)
			}
		case <-time.After(filesentryPositiveBackstop):
			t.Fatal("timeout waiting for normal-sized agent Finding to cancel")
		}
		finish()

		if got := cancelCount.Load(); got != 1 {
			t.Errorf("normal-sized agent Finding must cancel once, got %d calls", got)
		}
	})
}

func TestConsumeFindings_BlockMode_AgentOverflowCancels(t *testing.T) {
	findings := make(chan Finding)
	close(findings)
	overflow := make(chan Finding, 1)
	overflow <- Finding{
		Path:        "/tmp/overflow",
		PatternName: "OverflowSecret",
		Severity:    "critical",
		IsAgent:     true,
	}
	close(overflow)
	var cancelCount atomic.Int32

	wait := ConsumeFindings(ConsumerOpts{
		Watcher: &stubWatcher{ch: findings, overflow: overflow},
		Action:  config.ActionBlock,
		Cancel:  func() { cancelCount.Add(1) },
	})
	wait()

	if cancelCount.Load() != 1 {
		t.Fatalf("agent overflow must cancel exactly once, got %d", cancelCount.Load())
	}
}

func TestConsumeFindings_WarnMode_NoCancel(t *testing.T) {
	var buf bytes.Buffer
	var cancelCount atomic.Int32
	var hookCalls atomic.Int32

	w := makeWatcher(t,
		Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true},
		Finding{Path: "/tmp/y", PatternName: "OpenAI", Severity: "high", IsAgent: false},
	)

	wait := ConsumeFindings(ConsumerOpts{
		Watcher:   w,
		Action:    config.ActionWarn,
		Log:       &buf,
		OnFinding: func(_, _ string, _ bool) { hookCalls.Add(1) },
		Cancel:    func() { cancelCount.Add(1) },
	})
	wait()

	if cancelCount.Load() != 0 {
		t.Errorf("cancel must not fire in warn mode, got %d calls", cancelCount.Load())
	}
	if hookCalls.Load() != 2 {
		t.Errorf("OnFinding should be called once per finding, got %d", hookCalls.Load())
	}
	out := buf.String()
	if !strings.Contains(out, "DLP match in /tmp/x: AWS") {
		t.Errorf("missing log for first finding: %q", out)
	}
	if !strings.Contains(out, "DLP match in /tmp/y: OpenAI") {
		t.Errorf("missing log for second finding: %q", out)
	}
	if !strings.Contains(out, "(agent process)") {
		t.Errorf("agent suffix missing on agent finding: %q", out)
	}
}

func TestConsumeFindings_BlockMode_AgentFinding_CancelsOnce(t *testing.T) {
	var buf bytes.Buffer
	var cancelCount atomic.Int32
	var blockSeen Finding
	var blockSeenMu sync.Mutex

	w := makeWatcher(t,
		Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true},
		Finding{Path: "/tmp/y", PatternName: "Stripe", Severity: "critical", IsAgent: true},
		Finding{Path: "/tmp/z", PatternName: "Slack", Severity: "high", IsAgent: false},
	)

	wait := ConsumeFindings(ConsumerOpts{
		Watcher: w,
		Action:  config.ActionBlock,
		Log:     &buf,
		Cancel:  func() { cancelCount.Add(1) },
		OnBlock: func(f Finding) {
			blockSeenMu.Lock()
			defer blockSeenMu.Unlock()
			blockSeen = f
		},
	})
	wait()

	if cancelCount.Load() != 1 {
		t.Errorf("cancel must fire exactly once in block mode (first agent finding); got %d", cancelCount.Load())
	}
	blockSeenMu.Lock()
	got := blockSeen
	blockSeenMu.Unlock()
	if got.Path != "/tmp/x" {
		t.Errorf("OnBlock should see the FIRST agent finding (/tmp/x), got %q", got.Path)
	}
}

func TestConsumeFindings_BlockMode_NonAgentOnly_NoCancel(t *testing.T) {
	var buf bytes.Buffer
	var cancelCount atomic.Int32

	w := makeWatcher(t,
		Finding{Path: "/tmp/editor", PatternName: "AWS", Severity: "critical", IsAgent: false},
		Finding{Path: "/tmp/build", PatternName: "Stripe", Severity: "high", IsAgent: false},
	)

	wait := ConsumeFindings(ConsumerOpts{
		Watcher: w,
		Action:  config.ActionBlock,
		Log:     &buf,
		Cancel:  func() { cancelCount.Add(1) },
	})
	wait()

	if cancelCount.Load() != 0 {
		t.Errorf("cancel must not fire on non-agent findings (editor saves / build output); got %d", cancelCount.Load())
	}
}

func TestConsumeFindings_BlockMode_NilCancel_DegradesToWarn(t *testing.T) {
	var buf bytes.Buffer
	var blockFired atomic.Bool
	w := makeWatcher(t,
		Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true},
	)
	wait := ConsumeFindings(ConsumerOpts{
		Watcher: w,
		Action:  config.ActionBlock,
		Log:     &buf,
		Cancel:  nil,
		// OnBlock observes the enforcement decision. With Cancel == nil
		// there is no enforcement to observe, so OnBlock must not fire.
		OnBlock: func(_ Finding) { blockFired.Store(true) },
	})
	wait()

	if !strings.Contains(buf.String(), "DLP match in /tmp/x") {
		t.Errorf("log line missing: %q", buf.String())
	}
	if blockFired.Load() {
		t.Error("OnBlock must not fire when Cancel is nil (no enforcement actually happens)")
	}
}

func TestConsumeFindings_EmptyAction_DefaultsToWarn(t *testing.T) {
	var cancelCount atomic.Int32
	w := makeWatcher(t, Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true})
	wait := ConsumeFindings(ConsumerOpts{
		Watcher: w,
		Action:  "", // normalize sets this to warn; the consumer must be conservative even if validate is bypassed
		Cancel:  func() { cancelCount.Add(1) },
	})
	wait()

	if cancelCount.Load() != 0 {
		t.Errorf("empty action must not trigger cancel (defensive); got %d", cancelCount.Load())
	}
}

func TestConsumeFindings_NilLog_NoPanic(t *testing.T) {
	w := makeWatcher(t, Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true})
	wait := ConsumeFindings(ConsumerOpts{
		Watcher: w,
		Action:  config.ActionBlock,
		Log:     nil,
		Cancel:  func() {},
	})
	wait()
}

func TestWriteFindingLog_AgentSuffix(t *testing.T) {
	var buf bytes.Buffer
	writeFindingLog(&buf, Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "critical", IsAgent: true})
	got := buf.String()
	want := "pipelock: [file_sentry] DLP match in /tmp/x: AWS (severity=critical) (agent process)\n"
	if got != want {
		t.Errorf("agent log format drifted:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestWriteFindingLog_NonAgentNoSuffix(t *testing.T) {
	var buf bytes.Buffer
	writeFindingLog(&buf, Finding{Path: "/tmp/x", PatternName: "AWS", Severity: "high", IsAgent: false})
	got := buf.String()
	want := "pipelock: [file_sentry] DLP match in /tmp/x: AWS (severity=high)\n"
	if got != want {
		t.Errorf("non-agent log format drifted:\n  got:  %q\n  want: %q", got, want)
	}
}
