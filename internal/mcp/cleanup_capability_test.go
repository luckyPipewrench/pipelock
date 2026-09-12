// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestClassifyCleanupCapability covers the three states and, critically, that
// an unsupported platform is classified without consulting the probe, so a
// non-Linux no-op that returns nil is never read as available.
func TestClassifyCleanupCapability(t *testing.T) {
	denied := errors.New("prctl blocked")
	tests := []struct {
		name       string
		supported  bool
		probe      func() error
		wantState  CleanupState
		wantErr    error
		wantProbed bool
	}{
		{
			name:      "unsupported platform never probes",
			supported: false,
			// A probe that fails the test if it runs: unsupported must not
			// consult the kernel and must not read a no-op nil as available.
			probe:      func() error { t.Error("probe called on unsupported platform"); return nil },
			wantState:  CleanupUnsupported,
			wantProbed: false,
		},
		{
			name:       "supported and probe succeeds is available",
			supported:  true,
			probe:      func() error { return nil },
			wantState:  CleanupAvailable,
			wantProbed: true,
		},
		{
			name:       "supported but probe fails is denied and carries err",
			supported:  true,
			probe:      func() error { return denied },
			wantState:  CleanupDenied,
			wantErr:    denied,
			wantProbed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var probed bool
			got := classifyCleanupCapability(tc.supported, func() error {
				probed = true
				return tc.probe()
			})
			if got.State != tc.wantState {
				t.Errorf("state = %v, want %v", got.State, tc.wantState)
			}
			if !errors.Is(got.Err, tc.wantErr) {
				t.Errorf("err = %v, want %v", got.Err, tc.wantErr)
			}
			if got.State == CleanupAvailable && got.Err != nil {
				t.Errorf("available must carry no err, got %v", got.Err)
			}
			if probed != tc.wantProbed {
				t.Errorf("probed = %v, want %v", probed, tc.wantProbed)
			}
		})
	}
}

// TestCleanupCapabilityProbe_OnceUnderConcurrency proves the memoization: many
// concurrent callers probe the kernel exactly once, and every caller sees the
// same verdict. This is the "repeated initialization without repeated kernel
// probe" and "concurrent callers safe" acceptance.
func TestCleanupCapabilityProbe_OnceUnderConcurrency(t *testing.T) {
	var calls atomic.Int64
	p := &cleanupCapabilityProbe{
		supported: true,
		probe: func() error {
			calls.Add(1)
			return nil
		},
	}

	const goroutines = 64
	var wg sync.WaitGroup
	results := make([]CleanupCapability, goroutines)
	start := make(chan struct{})
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = p.capability()
		}(i)
	}
	close(start)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("probe called %d times, want exactly 1", got)
	}
	for i, r := range results {
		if r.State != CleanupAvailable {
			t.Fatalf("result[%d].State = %v, want CleanupAvailable", i, r.State)
		}
	}
	// A later call still returns the cached verdict without re-probing.
	if again := p.capability(); again.State != CleanupAvailable {
		t.Fatalf("cached call = %v, want CleanupAvailable", again.State)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe re-invoked after caching: %d calls, want 1", got)
	}
}

// TestCleanupCapabilityProbe_NoFalseSuccessOnDenied proves a failed probe is
// never cached or read as available, including across repeated calls.
func TestCleanupCapabilityProbe_NoFalseSuccessOnDenied(t *testing.T) {
	denied := errors.New("subreaper unavailable")
	var calls atomic.Int64
	p := &cleanupCapabilityProbe{
		supported: true,
		probe: func() error {
			calls.Add(1)
			return denied
		},
	}
	for range 3 {
		got := p.capability()
		if got.State != CleanupDenied {
			t.Fatalf("state = %v, want CleanupDenied", got.State)
		}
		if !errors.Is(got.Err, denied) {
			t.Fatalf("err = %v, want %v", got.Err, denied)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("probe called %d times, want exactly 1", got)
	}
}

// TestCleanupDegradedWarning locks the shared consequence wording and the
// strict-only remedy hint, so the startup report and the per-child warning
// cannot drift apart.
func TestCleanupDegradedWarning(t *testing.T) {
	err := errors.New("prctl: operation not permitted")

	best := cleanupDegradedWarning(err, true)
	if !strings.Contains(best, "session descendant cleanup degraded") {
		t.Errorf("missing degraded phrase: %q", best)
	}
	if !strings.Contains(best, cleanupDegradedConsequence) {
		t.Errorf("missing shared consequence: %q", best)
	}
	if !strings.Contains(best, "PR_SET_CHILD_SUBREAPER failed (prctl: operation not permitted)") {
		t.Errorf("missing wrapped error: %q", best)
	}
	if !strings.Contains(best, "Run with strict mode to fail closed instead.") {
		t.Errorf("best-effort hint should include the strict remedy: %q", best)
	}
	if !strings.HasSuffix(best, "\n") {
		t.Errorf("warning must end in newline: %q", best)
	}

	strict := cleanupDegradedWarning(err, false)
	if strings.Contains(strict, "Run with strict mode") {
		t.Errorf("strict-context warning must not suggest strict mode again: %q", strict)
	}
	if !strings.Contains(strict, cleanupDegradedConsequence) {
		t.Errorf("missing shared consequence: %q", strict)
	}
}

// TestWriteCleanupReport covers each state's operator-facing line, including
// that the unsupported line makes no kernel-cleanup claim and that the denied
// line's remedy hint tracks strict vs best-effort.
func TestWriteCleanupReport(t *testing.T) {
	denied := errors.New("prctl blocked")
	tests := []struct {
		name       string
		cap        CleanupCapability
		strictHint bool
		wantSubs   []string
		unwantSubs []string
	}{
		{
			name:     "available",
			cap:      CleanupCapability{State: CleanupAvailable},
			wantSubs: []string{"session descendant cleanup: available", "child subreaper enabled"},
		},
		{
			name:       "unsupported makes no cleanup claim",
			cap:        CleanupCapability{State: CleanupUnsupported},
			wantSubs:   []string{"unavailable on this platform", "cannot be adopted"},
			unwantSubs: []string{"available ("},
		},
		{
			name:       "denied best effort shows strict remedy",
			cap:        CleanupCapability{State: CleanupDenied, Err: denied},
			strictHint: true,
			wantSubs:   []string{"cleanup degraded", "prctl blocked", "Run with strict mode"},
		},
		{
			name:       "denied strict omits strict remedy",
			cap:        CleanupCapability{State: CleanupDenied, Err: denied},
			strictHint: false,
			wantSubs:   []string{"cleanup degraded", "prctl blocked"},
			unwantSubs: []string{"Run with strict mode"},
		},
		{
			name:       "denied plain stdio omits inapplicable strict remedy",
			cap:        CleanupCapability{State: CleanupDenied, Err: denied},
			strictHint: false,
			wantSubs:   []string{"cleanup degraded", "prctl blocked"},
			unwantSubs: []string{"Run with strict mode"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			writeCleanupReport(&buf, tc.cap, tc.strictHint)
			out := buf.String()
			for _, s := range tc.wantSubs {
				if !strings.Contains(out, s) {
					t.Errorf("output missing %q; got %q", s, out)
				}
			}
			for _, s := range tc.unwantSubs {
				if strings.Contains(out, s) {
					t.Errorf("output unexpectedly contains %q; got %q", s, out)
				}
			}
		})
	}
}

// TestReportCleanupCapability_ReportsBeforeReturning is the thin-wrapper check:
// it probes the process-wide capability, writes a non-empty report, and the
// returned capability matches what the report described. On the Linux test
// host the real probe succeeds, so this asserts the available path end to end
// without depending on kernel internals a fake could not prove.
func TestReportCleanupCapability_ReportsBeforeReturning(t *testing.T) {
	var buf strings.Builder
	got := ReportCleanupCapability(&buf, false)
	out := buf.String()
	if out == "" {
		t.Fatal("report wrote nothing")
	}
	// The returned state must match the line written.
	switch got.State {
	case CleanupAvailable:
		if !strings.Contains(out, "available") {
			t.Errorf("state Available but report %q", out)
		}
	case CleanupUnsupported:
		if !strings.Contains(out, "unavailable on this platform") {
			t.Errorf("state Unsupported but report %q", out)
		}
	case CleanupDenied:
		if !strings.Contains(out, "cleanup degraded") {
			t.Errorf("state Denied but report %q", out)
		}
	}
}
