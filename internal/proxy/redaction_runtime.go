// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
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
	required                   bool
}

func (p *Proxy) buildRedactionRuntime(cfg *config.Config) (*redactionRuntime, error) {
	matcher, err := p.buildRedactMatcher(cfg)
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
	return &redactionRuntime{
		matcher:                    matcher,
		limits:                     cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable:       allowlist,
		allowlistUnparseableRoutes: routes,
		providers:                  providers,
		configKey:                  redactionConfigKey(cfg),
		required:                   cfg.Redaction.Enabled,
	}, nil
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
	return currentRedactionRuntimeForConfig(cfg, &p.redactionRuntimePtr)
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

func currentRedactionRuntimeForConfig(cfg *config.Config, ptr *atomic.Pointer[redactionRuntime]) *redactionRuntime {
	if ptr != nil {
		if rt := ptr.Load(); rt != nil && rt.matcher != nil {
			if cfg != nil && rt.configKey == redactionConfigKey(cfg) {
				return rt
			}
		}
	}
	// No runtime published yet (startup, or cfg disables redaction). Fall
	// back to cfg so callers see the intended operator state. A populated
	// runtime whose configKey does not match cfg is treated the same way:
	// fail closed instead of mixing one policy's matcher with another
	// policy's receipts and canonical hash.
	if cfg == nil || !cfg.Redaction.Enabled {
		return nil
	}
	// cfg says redaction is required but no matcher is available — this can
	// only happen before startup setup runs. Keep the fail-closed sentinel
	// so request handlers block instead of silently skipping.
	return &redactionRuntime{
		limits:                     cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable:       append([]string(nil), cfg.Redaction.AllowlistUnparseable...),
		allowlistUnparseableRoutes: append([]redact.UnparseableRouteSpec(nil), cfg.Redaction.AllowlistUnparseableRoutes...),
		providers:                  nil,
		configKey:                  redactionConfigKey(cfg),
		required:                   true,
	}
}

func redactionConfigKey(cfg *config.Config) string {
	if cfg == nil || !cfg.Redaction.Enabled {
		return ""
	}
	payload, err := json.Marshal(cfg.Redaction)
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
