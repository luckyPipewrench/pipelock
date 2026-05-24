// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// FindingHook is the callback signature for metric / audit emission.
// Called for every finding regardless of action mode. Implementations
// must be safe for concurrent use; the consumer invokes the hook from
// a single goroutine but downstream callers may run in parallel.
type FindingHook func(patternName, severity string, isAgent bool)

// ConsumerOpts configures ConsumeFindings.
//
// The enforcement decision is intentionally split from the watcher: the
// Watcher is a pure observer that emits Finding values on a channel; the
// consumer reads that channel, logs each finding, records the metric, and
// then decides whether to escalate by calling Cancel.
//
// Cancel is only invoked when Action == config.ActionBlock AND the finding
// is attributed to a process in the agent tree (Finding.IsAgent). Non-agent
// writes (editor saves, build output, other system processes touching the
// watched directory) never trigger the block path. This matches the rule
// that file_sentry is a fail-closed boundary on the agent subprocess, not
// a general filesystem guard.
type ConsumerOpts struct {
	// Watcher is the watcher whose Findings() channel will be drained.
	// Required.
	Watcher Watcher
	// Action is the enforcement mode. Empty defaults to warn. Validated by
	// the config layer so values other than warn / block never reach here.
	Action string
	// Log is the human-readable sink (typically the proxy stderr). May be
	// nil — log lines are then dropped.
	Log io.Writer
	// OnFinding is invoked once per finding for metric / audit emission.
	// May be nil.
	OnFinding FindingHook
	// Cancel is the proxy context cancel function. Called once on the first
	// block-action + IsAgent finding. May be nil — Cancel == nil means
	// "block degrades to warn" (used by tests + diag paths that do not own
	// the proxy lifecycle).
	Cancel func()
	// OnBlock is an optional callback invoked just before Cancel is called.
	// Used by tests to observe the enforcement decision; production callers
	// typically pass nil. Always invoked synchronously from the consumer
	// goroutine before Cancel.
	OnBlock func(Finding)
}

// ConsumeFindings drains opts.Watcher.Findings() in a background goroutine,
// logging each finding and emitting metrics. Returns a function that blocks
// until the consumer goroutine has finished draining (typically called from
// a defer after Watcher.Close()).
//
// Behavior matrix:
//
//	Action="warn" or "" → log + metric for every finding; Cancel never fires
//	Action="block"      → log + metric for every finding; on the first finding
//	                       with IsAgent=true, Cancel is invoked exactly once
//	                       AFTER the log/metric for that finding. Subsequent
//	                       findings keep emitting logs/metrics but Cancel is
//	                       not called again (it's already fired; ctx is gone).
//
// Logging is fire-and-forget; write errors on the Log writer are ignored.
func ConsumeFindings(opts ConsumerOpts) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		blockMode := opts.Action == config.ActionBlock
		cancelled := false
		for f := range opts.Watcher.Findings() {
			writeFindingLog(opts.Log, f)
			if opts.OnFinding != nil {
				opts.OnFinding(f.PatternName, f.Severity, f.IsAgent)
			}
			if blockMode && f.IsAgent && opts.Cancel != nil && !cancelled {
				cancelled = true
				if opts.OnBlock != nil {
					opts.OnBlock(f)
				}
				opts.Cancel()
			}
		}
	}()
	return func() { <-done }
}

// writeFindingLog writes the human-readable log line for one finding. Split
// out so the format is exercised by a small dedicated test and matches the
// previous in-line format byte-for-byte.
func writeFindingLog(w io.Writer, f Finding) {
	if w == nil {
		return
	}
	agent := ""
	if f.IsAgent {
		agent = " (agent process)"
	}
	_, _ = fmt.Fprintf(w,
		"pipelock: [file_sentry] DLP match in %s: %s (severity=%s)%s\n",
		f.Path, f.PatternName, f.Severity, agent)
}
