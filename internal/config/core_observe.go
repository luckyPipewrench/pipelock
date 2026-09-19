// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"time"
)

// CoreObserveDecision reports whether one core response finding on one host is
// operator-declared as observe-only.
//
// The decision is re-evaluated at scan time rather than cached from config
// load. A long-running proxy loaded a config months ago; if the declared
// expiry has since passed, the exception must stop applying without waiting
// for a reload. Validation refuses an already-expired entry at load, and this
// check refuses one that expired while the process was running. Both
// directions fail closed to blocking, which is the shipped behavior.
func (c *Config) CoreObserveDecision(host, patternName string, now time.Time) (CoreObserveException, bool) {
	if c == nil {
		return CoreObserveException{}, false
	}
	return MatchCoreObserveException(c.ResponseScanning.CoreObserveExceptions, host, patternName, now)
}

// MatchCoreObserveException is the shared matcher. The scanner and the config
// validator both go through it so they agree by construction about what "an
// active exception" means.
func MatchCoreObserveException(entries []CoreObserveException, host, patternName string, now time.Time) (CoreObserveException, bool) {
	host = canonicalCoreObserveHost(host)
	if host == "" || strings.TrimSpace(patternName) == "" {
		return CoreObserveException{}, false
	}
	// Only a real core pattern can be observed. A configured (non-core)
	// pattern already has response_scanning.suppress and action, so accepting
	// one here would silently widen this valve beyond the floor it exists for.
	if !IsCoreResponsePatternName(patternName) {
		return CoreObserveException{}, false
	}
	for _, entry := range entries {
		if canonicalCoreObserveHost(entry.Host) != host {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(entry.Pattern), strings.TrimSpace(patternName)) {
			continue
		}
		if coreObserveExpired(entry.Expires, now) {
			// A matching but expired entry is NOT a match, and no later entry
			// may rescue it: continue so a duplicate live entry for the same
			// host and pattern still wins, but an expired one never does.
			continue
		}
		return entry, true
	}
	return CoreObserveException{}, false
}

// coreObserveExpired reports whether expires is absent, unparseable, or past.
// Every one of those is treated as expired so a malformed date can never
// extend an exception; validation rejects them at load, and this is the
// runtime backstop for a config that reached the scanner another way.
func coreObserveExpired(expires string, now time.Time) bool {
	trimmed := strings.TrimSpace(expires)
	if trimmed == "" {
		return true
	}
	parsed, err := time.Parse("2006-01-02", trimmed)
	if err != nil {
		return true
	}
	// The entry covers the whole of its expires day, matching the
	// YYYY-MM-DD semantics the other temporary exceptions use.
	return now.UTC().Truncate(24 * time.Hour).After(parsed)
}

// canonicalCoreObserveHost lowercases and strips a trailing dot so a declared
// host and an observed destination compare the same way the host-match helpers
// elsewhere in this package do.
func canonicalCoreObserveHost(host string) string {
	trimmed := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(trimmed, ".")
}
