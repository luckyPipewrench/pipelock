// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// stubWatcher is a Watcher that drives Findings() from a pre-seeded
// channel. Arm / Start / Close are no-ops sufficient for testing the
// consumer's enforcement decisions in isolation from fsnotify.
type stubWatcher struct{ ch chan Finding }

func (s *stubWatcher) Arm() error                    { return nil }
func (s *stubWatcher) Start(_ context.Context) error { return nil }
func (s *stubWatcher) Findings() <-chan Finding      { return s.ch }
func (s *stubWatcher) Close() error                  { return nil }

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
	return &stubWatcher{ch: ch}
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
