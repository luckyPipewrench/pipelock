// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestCoreFloorPredicatesDoNotDrift locks the immutable-floor membership
// decision shared by the request-body floor (shouldHardBlockRequestDLP, here in
// internal/proxy) and the text-DLP floor (scanner.IsCoreCriticalMatch, consulted
// by the MCP input and A2A floors). Both route through
// config.IsCoreDLPPatternName, so if one consumer's view of "immutable core
// credential" drifts from the other, an operator could downgrade a core
// credential on one transport while it stays blocked on another. The guard: for
// every core pattern name both predicates hard-block AND treat the pattern as
// non-downgradable (a pattern_actions warn override is ignored); for a non-core
// critical pattern IsCoreCriticalMatch is false and the body floor honors a
// pattern_actions warn downgrade.
func TestCoreFloorPredicatesDoNotDrift(t *testing.T) {
	corePatterns := config.CoreDLPPatterns()
	if len(corePatterns) == 0 {
		t.Fatal("no core DLP patterns returned; enumeration is miscalibrated")
	}

	for _, p := range corePatterns {
		p := p
		t.Run("core/"+p.Name, func(t *testing.T) {
			// Load-bearing for parity: the body floor only considers Critical
			// findings, so a core pattern that is not Critical would block on
			// the MCP/A2A floor but not on the body floor.
			if p.Severity != config.SeverityCritical {
				t.Fatalf("core pattern %q severity = %q, want critical (body floor only blocks critical)", p.Name, p.Severity)
			}
			match := scanner.TextDLPMatch{PatternName: p.Name, Severity: p.Severity}

			if !scanner.IsCoreCriticalMatch(match) {
				t.Fatalf("scanner.IsCoreCriticalMatch(%q) = false, want true", p.Name)
			}

			// The body floor must hard-block the core pattern even when the
			// operator points a pattern_actions warn override at it: the core
			// floor is immutable and cannot be downgraded.
			cfg := config.Defaults()
			cfg.RequestBodyScanning.PatternActions = map[string]string{p.Name: config.ActionWarn}
			if !shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfg) {
				t.Fatalf("shouldHardBlockRequestDLP(core %q, pattern_actions=warn) = false; core floor must be non-downgradable", p.Name)
			}
		})
	}

	// A non-core critical pattern is blocked by the body floor by severity but
	// is downgradable by pattern_actions, and is NOT part of the immutable core
	// floor consulted by the MCP/A2A predicate. Discover one from the defaults
	// rather than hardcoding a name.
	nonCore := firstNonCoreCriticalPattern(t)
	match := scanner.TextDLPMatch{PatternName: nonCore, Severity: config.SeverityCritical}

	if scanner.IsCoreCriticalMatch(match) {
		t.Fatalf("scanner.IsCoreCriticalMatch(non-core %q) = true, want false", nonCore)
	}

	// Without a downgrade, the body floor blocks a non-core critical by severity.
	cfgEnforce := config.Defaults()
	if !shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfgEnforce) {
		t.Fatalf("shouldHardBlockRequestDLP(non-core critical %q) = false, want true (blocks by severity)", nonCore)
	}
	// A pattern_actions warn override downgrades a non-core critical, unlike the
	// immutable core floor above.
	cfgWarn := config.Defaults()
	cfgWarn.RequestBodyScanning.PatternActions = map[string]string{nonCore: config.ActionWarn}
	if shouldHardBlockRequestDLP([]scanner.TextDLPMatch{match}, cfgWarn) {
		t.Fatalf("shouldHardBlockRequestDLP(non-core %q, pattern_actions=warn) = true; a non-core critical must be downgradable", nonCore)
	}
}

// firstNonCoreCriticalPattern returns the name of a built-in critical DLP
// pattern that is not part of the immutable core floor.
func firstNonCoreCriticalPattern(t *testing.T) string {
	t.Helper()
	for _, p := range config.Defaults().DLP.Patterns {
		if p.Severity == config.SeverityCritical && !config.IsCoreDLPPatternName(p.Name) {
			return p.Name
		}
	}
	t.Fatal("no non-core critical DLP pattern found in defaults; cannot exercise the non-core arm")
	return ""
}
