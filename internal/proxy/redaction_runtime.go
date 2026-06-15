// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// redactionRuntime snapshots every request-body redaction input that must stay
// consistent for a single request or tunnel. Callers load this atomically
// instead of mixing cfg.Redaction fields with an independently-swapped matcher.
type redactionRuntime struct {
	matcher                    *redact.Matcher
	limits                     redact.Limits
	allowlistUnparseable       []string
	allowlistUnparseableRoutes []redact.UnparseableRouteSpec
	providers                  *redact.ProviderRegistry
	configKey                  string
	// previous keeps the last matching snapshot available during reload
	// publication, so old cfg/scanner request snapshots do not spuriously
	// fail closed after the new runtime is staged.
	previous *redactionRuntime
	required bool
}

func (p *Proxy) buildRedactionRuntimeWithScanner(cfg *config.Config, sc *scanner.Scanner) (*redactionRuntime, error) {
	matcher, err := p.buildRedactMatcherWithScanner(cfg, sc)
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return nil, nil
	}
	providers, err := cfg.Redaction.BuildProviderRegistry()
	if err != nil {
		return nil, fmt.Errorf("build redaction provider registry: %w", err)
	}
	allowlist := append([]string(nil), cfg.Redaction.AllowlistUnparseable...)
	routes := append([]redact.UnparseableRouteSpec(nil), cfg.Redaction.AllowlistUnparseableRoutes...)
	configKey, err := redactionConfigKeyForScanner(cfg, sc)
	if err != nil {
		return nil, fmt.Errorf("compute redaction config key: %w", err)
	}
	rt := &redactionRuntime{
		matcher:                    matcher,
		limits:                     cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable:       allowlist,
		allowlistUnparseableRoutes: routes,
		providers:                  providers,
		configKey:                  configKey,
		required:                   cfg.Redaction.Enabled,
	}
	if previous := p.redactionRuntimePtr.Load(); previous != nil && previous.matcher != nil && previous.configKey != rt.configKey {
		// Carry only the IMMEDIATE prior runtime as a one-hop fallback for the
		// transient publish window between redactionRuntimePtr.Store and the
		// scannerPtr swap in Reload. Shallow-copy and zero the predecessor's
		// own .previous so chain depth stays bounded at 1 across many
		// different-key reloads; otherwise long-running pods that rotate
		// file/env secrets would accumulate every prior matcher in memory.
		// The matcher and provider pointers are shared, so the copy is cheap.
		snap := *previous
		snap.previous = nil
		rt.previous = &snap
	}
	return rt, nil
}

// RedactionRuntimePtr returns the atomic pointer to the redaction runtime
// snapshot. Reverse-proxy handlers use this to receive hot-reload updates
// without reconstructing policy from multiple atomics.
func (p *Proxy) RedactionRuntimePtr() *atomic.Pointer[redactionRuntime] {
	return &p.redactionRuntimePtr
}

// currentRedactionRuntimeFor returns the runtime that matches cfg's current
// redaction policy. When redaction is enabled but the staged runtime does not
// match the request-scoped config snapshot (during reload windows), callers get
// a fail-closed sentinel instead of silently skipping redaction.
func (p *Proxy) currentRedactionRuntimeFor(cfg *config.Config) *redactionRuntime {
	return currentRedactionRuntimeForConfig(cfg, &p.redactionRuntimePtr, p.scannerPtr.Load())
}

// CurrentRedactionConfigFor returns the redaction matcher and limits that
// correspond to cfg's current redaction policy. Callers outside package proxy
// use this instead of mixing cfg.Redaction with independently-swapped atomics.
func (p *Proxy) CurrentRedactionConfigFor(cfg *config.Config) (*redact.Matcher, redact.Limits, bool) {
	rt := p.currentRedactionRuntimeFor(cfg)
	if rt == nil {
		return nil, redact.Limits{}, false
	}
	return rt.matcher, rt.limits, rt.required
}

func currentRedactionRuntimeForConfig(cfg *config.Config, ptr *atomic.Pointer[redactionRuntime], scanners ...*scanner.Scanner) *redactionRuntime {
	var (
		expectedKey string
		keyErr      error
	)
	if len(scanners) > 0 && scanners[0] != nil {
		expectedKey, keyErr = redactionConfigKeyForScanner(cfg, scanners[0])
	} else {
		expectedKey, keyErr = redactionConfigKey(cfg)
	}
	if keyErr == nil && ptr != nil {
		if rt := ptr.Load(); rt != nil && rt.matcher != nil {
			for candidate := rt; candidate != nil; candidate = candidate.previous {
				if candidate.matcher == nil {
					continue
				}
				if cfg != nil && candidate.configKey == expectedKey {
					return candidate
				}
			}
		}
	}
	// No matching runtime: startup before setup, cfg disables redaction, a
	// reload-window key mismatch, or a key-computation error (keyErr != nil).
	// Fall back to cfg intent. A populated runtime whose configKey does not
	// match is treated the same way: fail closed instead of mixing one
	// policy's matcher with another policy's receipts and canonical hash.
	if cfg == nil || !cfg.Redaction.Enabled {
		return nil
	}
	// cfg requires redaction but no matching matcher is available (startup not
	// yet run, or the key could not be computed). Return the fail-closed
	// sentinel so request handlers block instead of silently skipping. On a
	// key error expectedKey is empty; the sentinel's nil matcher is what
	// enforces the block, not its key.
	return &redactionRuntime{
		limits:                     cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable:       append([]string(nil), cfg.Redaction.AllowlistUnparseable...),
		allowlistUnparseableRoutes: append([]redact.UnparseableRouteSpec(nil), cfg.Redaction.AllowlistUnparseableRoutes...),
		providers:                  nil,
		configKey:                  expectedKey,
		required:                   true,
	}
}

// redactionConfigKey returns the canonical redaction-policy key for cfg, or ""
// when redaction is disabled. The canonicalization that makes the key invariant
// to the per-agent deep-copy YAML round-trip, plus its memoisation, live on
// config.Config; see Config.CanonicalRedactionKey. A non-nil error means the
// key could not be computed and callers must fail closed rather than treat the
// empty string as "disabled".
func redactionConfigKey(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", nil
	}
	return cfg.CanonicalRedactionKey()
}

func redactionConfigKeyForScanner(cfg *config.Config, sc *scanner.Scanner) (string, error) {
	base, err := redactionConfigKey(cfg)
	if err != nil {
		return "", err
	}
	scannerKey := scannerRedactionKey(sc)
	if base == "" || scannerKey == "" {
		return base, nil
	}
	payload, err := json.Marshal(struct {
		Config  string `json:"config"`
		Scanner string `json:"scanner"`
	}{
		Config:  base,
		Scanner: scannerKey,
	})
	if err != nil {
		return "", fmt.Errorf("marshal redaction config+scanner key: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func scannerRedactionKey(sc *scanner.Scanner) string {
	if sc == nil {
		return ""
	}
	values := sc.RedactionSecretValues()
	if len(values.Env) == 0 && len(values.File) == 0 {
		return ""
	}
	values.Env = append([]string(nil), values.Env...)
	values.File = append([]string(nil), values.File...)
	sort.Strings(values.Env)
	sort.Strings(values.File)
	payload, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func applyBodyScanRedaction(req *BodyScanRequest, rt *redactionRuntime) {
	if req == nil || rt == nil {
		return
	}
	req.RedactionRequired = rt.required
	req.RedactMatcher = rt.matcher
	req.RedactLimits = rt.limits
	req.RedactAllowlistUnparseable = rt.allowlistUnparseable
	req.RedactAllowlistUnparseableRoutes = rt.allowlistUnparseableRoutes
	req.RedactProviderRegistry = rt.providers
}
