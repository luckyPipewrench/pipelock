// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/filesentry"
)

// TestFileSentryArmFailureStandaloneSummary pins the operator-facing contract of
// the reworked arm-failure renderer: the first line is a standalone summary
// carrying the accurate skipped/unarmed subtree count, the applicable remedy
// follows, and the original joined detail lines come last under "details:".
// It also pins that the sentinel errors.Is chain survives the rewrap and that
// best_effort is offered only for failures it can actually resolve.
func TestFileSentryArmFailureStandaloneSummary(t *testing.T) {
	requiredMultiPath := func() error {
		inner := errors.Join(
			fmt.Errorf("cannot monitor subtree %q beneath watch root %q: %w", "/srv/data/blocked", "/srv/data", fs.ErrPermission),
			fmt.Errorf("cannot monitor subtree %q beneath watch root %q: %w", "/srv/data/secret", "/srv/data", fs.ErrPermission),
		)
		cause := errors.Join(filesentry.ErrRequiredWatchPath, inner)
		return fmt.Errorf("filesentry: incomplete watch coverage: %w", cause)
	}
	noArmedWithCount := func() error {
		cause := fmt.Errorf("cannot monitor subtree %q beneath watch root %q: %w", "/x/missing", "/x/missing", fs.ErrNotExist)
		return fmt.Errorf("%w: %w", filesentry.ErrNoWatchPaths, cause)
	}
	incompleteBestEffort := func() error {
		return fmt.Errorf("filesentry: incomplete watch coverage: %w",
			fmt.Errorf("cannot monitor subtree %q beneath watch root %q: %w", "/tmp/w/blocked", "/tmp/w", fs.ErrPermission))
	}

	tests := []struct {
		name            string
		armErr          error
		degraded        int
		wantIs          error  // sentinel that must remain reachable via errors.Is
		wantSummary     string // exact first line
		mustFailClosed  bool   // true => best_effort must NOT be offered
		wantDetailLines []string
		forbidFirstLine []string // substrings that must not appear fused into the summary
	}{
		{
			name:            "required multi-path failure",
			armErr:          requiredMultiPath(),
			degraded:        2,
			wantIs:          filesentry.ErrRequiredWatchPath,
			wantSummary:     "file sentry failed to arm watches (feature is enabled): 2 skipped/unarmed watch subtree(s)",
			mustFailClosed:  true,
			wantDetailLines: []string{"/srv/data/blocked", "/srv/data/secret", "permission denied", "required watch coverage unavailable"},
			forbidFirstLine: []string{"incomplete watch coverage", "/srv/data", "required watch coverage unavailable"},
		},
		{
			name:            "no armed paths with a counted root",
			armErr:          noArmedWithCount(),
			degraded:        1,
			wantIs:          filesentry.ErrNoWatchPaths,
			wantSummary:     "file sentry failed to arm watches (feature is enabled): 1 skipped/unarmed watch subtree(s)",
			mustFailClosed:  true,
			wantDetailLines: []string{"/x/missing", "no watch paths armed"},
			forbidFirstLine: []string{"/x/missing", "no watch paths armed"},
		},
		{
			name:            "zero-count no watchable paths",
			armErr:          filesentry.ErrNoWatchPaths,
			degraded:        0,
			wantIs:          filesentry.ErrNoWatchPaths,
			wantSummary:     "file sentry failed to arm watches (feature is enabled): no watch paths could be armed",
			mustFailClosed:  true,
			wantDetailLines: []string{"no watch paths armed"},
			forbidFirstLine: []string{"no watch paths armed"},
		},
		{
			name:            "incomplete coverage best_effort applies",
			armErr:          incompleteBestEffort(),
			degraded:        1,
			wantIs:          nil,
			wantSummary:     "file sentry failed to arm watches (feature is enabled): 1 skipped/unarmed watch subtree(s)",
			mustFailClosed:  false,
			wantDetailLines: []string{"/tmp/w/blocked", "permission denied"},
			forbidFirstLine: []string{"incomplete watch coverage", "/tmp/w"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rendered := fileSentryArmFailure(tt.armErr, tt.degraded)
			got := rendered.Error()
			if errors.Is(tt.armErr, filesentry.ErrNoWatchPaths) {
				if !strings.Contains(got, "at least one file_sentry.watch_paths entry names an existing directory") {
					t.Errorf("zero-coverage failure must explain how to establish coverage:\n%s", got)
				}
				for _, inertRemedy := range []string{"add a file_sentry.ignore_patterns entry", "drop required: true"} {
					if strings.Contains(got, inertRemedy) {
						t.Errorf("zero-coverage failure offered an ineffective remedy %q:\n%s", inertRemedy, got)
					}
				}
			}

			// Sentinel chain preserved through the rewrap.
			if tt.wantIs != nil && !errors.Is(rendered, tt.wantIs) {
				t.Fatalf("errors.Is(rendered, %v) = false; sentinel chain lost:\n%s", tt.wantIs, got)
			}

			lines := strings.SplitN(got, "\n", 2)
			firstLine := lines[0]
			if firstLine != tt.wantSummary {
				t.Fatalf("first line = %q, want standalone summary %q\nfull:\n%s", firstLine, tt.wantSummary, got)
			}
			// A zero-count failure must never fabricate a "0" count.
			if tt.degraded == 0 && strings.Contains(firstLine, "0 ") {
				t.Errorf("zero-count summary fabricated a count: %q", firstLine)
			}
			for _, forbidden := range tt.forbidFirstLine {
				if strings.Contains(firstLine, forbidden) {
					t.Errorf("summary fused a detail into the first line: %q contains %q", firstLine, forbidden)
				}
			}

			// Ordering: summary, then remedy, then details, then the detail lines.
			iRemedy := strings.Index(got, "remedies:")
			iDetails := strings.Index(got, "\ndetails:\n")
			if iRemedy <= 0 {
				t.Fatalf("no remedy rendered:\n%s", got)
			}
			if iDetails <= iRemedy {
				t.Fatalf("details must follow the remedy (iRemedy=%d iDetails=%d):\n%s", iRemedy, iDetails, got)
			}

			// Remedy correctness: best_effort offered only when it can resolve.
			offersBestEffort := strings.Contains(got, "set file_sentry.best_effort: true to trade coverage")
			deniesBestEffort := strings.Contains(got, "does NOT apply to this failure")
			if tt.mustFailClosed {
				if strings.Contains(got, "drop required: true") {
					t.Errorf("removing required alone cannot repair strict coverage:\n%s", got)
				}
				if offersBestEffort {
					t.Errorf("must-fail-closed error offered best_effort:\n%s", got)
				}
				if !deniesBestEffort {
					t.Errorf("must-fail-closed error missing the best_effort-does-not-apply note:\n%s", got)
				}
			} else {
				if !offersBestEffort {
					t.Errorf("resolvable failure did not offer best_effort:\n%s", got)
				}
			}

			// Detail lines preserved verbatim, after the details label.
			for _, want := range tt.wantDetailLines {
				idx := strings.Index(got, want)
				if idx < 0 {
					t.Errorf("detail %q missing from rendered error:\n%s", want, got)
					continue
				}
				if idx < iDetails {
					t.Errorf("detail %q appeared before the details label:\n%s", want, got)
				}
			}
		})
	}
}

// TestServer_StartFileSentryFailureShowsStandaloneSummary drives the real
// watcher through the server startup seam: a required, nonexistent watch root
// produces a genuine Arm failure with a real DegradedPathCount, and the
// consumer must render the standalone summary (not the fused headline) while
// keeping the fail-closed sentinel chain intact.
func TestServer_StartFileSentryFailureShowsStandaloneSummary(t *testing.T) {
	cfg := config.Defaults()
	cfg.FileSentry.Enabled = true
	cfg.FileSentry.WatchPaths = []config.WatchPath{
		{Path: filepath.Join(t.TempDir(), "nonexistent-required"), Required: true},
	}
	s, _ := newTestServer(t, nil)

	_, err := s.startFileSentry(context.Background(), cfg, func() {})
	if err == nil {
		t.Fatal("startFileSentry returned nil; a required nonexistent root must fail closed")
	}
	if !errors.Is(err, filesentry.ErrRequiredWatchPath) {
		t.Fatalf("errors.Is(err, ErrRequiredWatchPath) = false; got %v", err)
	}

	firstLine := strings.SplitN(err.Error(), "\n", 2)[0]
	if !strings.HasPrefix(firstLine, "file sentry failed to arm watches (feature is enabled): ") {
		t.Fatalf("first line is not the standalone summary: %q", firstLine)
	}
	if !strings.Contains(firstLine, "skipped/unarmed watch subtree(s)") {
		t.Fatalf("summary missing a real skipped/unarmed count: %q", firstLine)
	}
	if strings.Contains(firstLine, "incomplete watch coverage") {
		t.Fatalf("headline fused with the joined detail chain: %q", firstLine)
	}
	// A required-root failure must not advertise best_effort as a fix.
	if strings.Contains(err.Error(), "set file_sentry.best_effort: true to trade coverage") {
		t.Errorf("required-root failure offered best_effort:\n%s", err.Error())
	}
}

func TestServer_StartFileSentryIgnoredRootRemedy(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.FileSentry.Enabled = true
	cfg.FileSentry.WatchPaths = []config.WatchPath{{Path: root}}
	cfg.FileSentry.IgnorePatterns = []string{filepath.Base(root)}
	s, _ := newTestServer(t, nil)

	_, err := s.startFileSentry(context.Background(), cfg, func() {})
	if !errors.Is(err, filesentry.ErrNoWatchPaths) {
		t.Fatalf("ignored root error = %v, want ErrNoWatchPaths", err)
	}
	if !strings.Contains(err.Error(), "file_sentry.ignore_patterns does not exclude it") {
		t.Fatalf("missing remedy for excluded watch root: %v", err)
	}

	// Apply the advertised remedy and prove startup can establish coverage.
	cfg.FileSentry.IgnorePatterns = nil
	stop, err := s.startFileSentry(context.Background(), cfg, func() {})
	if err != nil {
		t.Fatalf("startup after removing the root exclusion: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop file sentry: %v", err)
	}
}
