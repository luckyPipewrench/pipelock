// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"sync"
)

// CleanupState is the availability of orphaned-descendant cleanup for MCP
// subprocesses. Cleanup relies on PR_SET_CHILD_SUBREAPER (Linux) so a
// grandchild that escapes the direct child's process group via setsid or a
// double fork still reparents to pipelock and can be reaped at session exit.
type CleanupState int

const (
	// CleanupAvailable means the kernel accepted the subreaper request.
	CleanupAvailable CleanupState = iota
	// CleanupUnsupported means the platform cannot provide subreaper-based
	// cleanup at all (every non-Linux target). The MCP helper is a no-op
	// there and returns nil, which must never be read as success.
	CleanupUnsupported
	// CleanupDenied means the platform should support the subreaper but the
	// kernel refused the request (for example a seccomp filter blocking
	// prctl, or a kernel too old to know the option). Err carries the failure.
	CleanupDenied
)

// CleanupCapability is the result of probing orphan-cleanup availability.
type CleanupCapability struct {
	State CleanupState
	// Err is set only for CleanupDenied and is the error the kernel probe
	// returned. It is nil for CleanupAvailable and CleanupUnsupported.
	Err error
}

// classifyCleanupCapability derives the capability from a platform-support
// flag and a probe. It runs the probe only on a supporting platform: a
// non-Linux no-op returns nil, and treating that nil as availability would
// claim kernel-backed cleanup that does not exist.
func classifyCleanupCapability(supported bool, probe func() error) CleanupCapability {
	if !supported {
		return CleanupCapability{State: CleanupUnsupported}
	}
	if err := probe(); err != nil {
		return CleanupCapability{State: CleanupDenied, Err: err}
	}
	return CleanupCapability{State: CleanupAvailable}
}

// cleanupCapabilityProbe memoizes MCP's startup probe. Pipelock leaves the
// process-wide subreaper setting enabled for its lifetime; concurrent and
// repeated MCP initialization therefore share the initial probe result.
type cleanupCapabilityProbe struct {
	supported bool
	probe     func() error
	once      sync.Once
	result    CleanupCapability
}

func (p *cleanupCapabilityProbe) capability() CleanupCapability {
	p.once.Do(func() {
		p.result = classifyCleanupCapability(p.supported, p.probe)
	})
	return p.result
}

// defaultCleanupProbe is the process-wide probe. cleanupPlatformSupported is a
// build-tagged constant (true on Linux, false elsewhere) and enableSubreaper is
// the real kernel call, so the first read arms the subreaper and every later
// read returns the same cached verdict.
var defaultCleanupProbe = &cleanupCapabilityProbe{
	supported: cleanupPlatformSupported,
	probe:     enableSubreaper,
}

// cleanupCapability reports whether pipelock can adopt and reap orphaned MCP
// descendants, probing the kernel once for the life of the process.
func cleanupCapability() CleanupCapability {
	return defaultCleanupProbe.capability()
}

// cleanupDegradedConsequence is the operator-facing consequence of losing
// orphan cleanup. It is defined once so the startup report and the per-child
// warning cannot drift apart.
const cleanupDegradedConsequence = "Detached descendants can survive session exit and can block proxy shutdown by retaining inherited I/O."

// cleanupDegradedWarning renders the degraded-cleanup warning. strictHint adds
// the fail-closed remedy, which applies only where a strict mode exists to
// refuse the launch (the sandbox proxy), not the plain stdio path.
func cleanupDegradedWarning(err error, strictHint bool) string {
	msg := fmt.Sprintf("pipelock: warning: session descendant cleanup degraded: PR_SET_CHILD_SUBREAPER failed (%v). %s", err, cleanupDegradedConsequence)
	if strictHint {
		msg += " Run with strict mode to fail closed instead."
	}
	return msg + "\n"
}

// ReportCleanupCapability probes orphan-cleanup availability once and reports
// it to logW before any MCP server is launched, so the operator learns the
// state up front instead of only seeing a per-child warning when it fails. It
// returns the capability; it does not decide the launch. The strict refusal
// still runs against the same probe result inside the sandbox proxy, so this
// report can never turn a denied capability into a successful launch.
//
// strictHint adds the remedy for a best-effort sandbox launch. It must be
// false for plain stdio, which has no strict-mode cleanup gate, and for a
// sandbox launch that is already strict.
func ReportCleanupCapability(logW io.Writer, strictHint bool) CleanupCapability {
	c := cleanupCapability()
	writeCleanupReport(logW, c, strictHint)
	return c
}

// writeCleanupReport renders one capability report to logW. Split from
// ReportCleanupCapability so every state can be exercised without the
// process-wide probe cache. strictHint picks the remedy wording only.
func writeCleanupReport(logW io.Writer, c CleanupCapability, strictHint bool) {
	switch c.State {
	case CleanupAvailable:
		_, _ = fmt.Fprint(logW, "pipelock: session descendant cleanup: available (child subreaper enabled)\n")
	case CleanupUnsupported:
		_, _ = fmt.Fprint(logW, "pipelock: session descendant cleanup: unavailable on this platform (orphaned MCP descendants cannot be adopted and may survive session exit)\n")
	case CleanupDenied:
		_, _ = fmt.Fprint(logW, cleanupDegradedWarning(c.Err, strictHint))
	}
}
