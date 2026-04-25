// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// redactionRuntime snapshots every request-body redaction input that must stay
// consistent for a single request or tunnel. Callers load this atomically
// instead of mixing cfg.Redaction fields with an independently-swapped matcher.
type redactionRuntime struct {
	matcher              *redact.Matcher
	limits               redact.Limits
	allowlistUnparseable []string
	configKey            string
	required             bool
}

func (p *Proxy) buildRedactionRuntime(cfg *config.Config) (*redactionRuntime, error) {
	matcher, err := p.buildRedactMatcher(cfg)
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return nil, nil
	}
	allowlist := append([]string(nil), cfg.Redaction.AllowlistUnparseable...)
	return &redactionRuntime{
		matcher:              matcher,
		limits:               cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable: allowlist,
		configKey:            redactionConfigKey(cfg),
		required:             cfg.Redaction.Enabled,
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
	// Trust whatever the reload path stored last. Earlier versions of this
	// factory compared the caller's `cfg` hash against the stored runtime's
	// `configKey`; during hot-reload, the cfgPtr and redactionRuntimePtr
	// atomics are updated with a gap of a few instructions, so a request
	// landing in that window would see OLD cfg + NEW runtime, the hashes
	// would disagree, and the factory would return a fail-closed sentinel
	// (matcher nil, required true) even though the freshly-published
	// runtime was authoritative. The reload-time invariant is that
	// `redactionRuntimePtr` reflects the current policy: nil when disabled,
	// non-nil with a populated matcher when enabled. Honor that directly
	// and stop racing with our own reload sequence.
	if ptr != nil {
		if rt := ptr.Load(); rt != nil && rt.matcher != nil {
			return rt
		}
	}
	// No runtime published yet (startup, or cfg disables redaction). Fall
	// back to cfg so callers see the intended operator state.
	if cfg == nil || !cfg.Redaction.Enabled {
		return nil
	}
	// cfg says redaction is required but no matcher is available — this can
	// only happen before startup setup runs. Keep the fail-closed sentinel
	// so request handlers block instead of silently skipping.
	return &redactionRuntime{
		limits:               cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable: append([]string(nil), cfg.Redaction.AllowlistUnparseable...),
		configKey:            redactionConfigKey(cfg),
		required:             true,
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
}
