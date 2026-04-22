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

func currentRedactionRuntimeForConfig(cfg *config.Config, ptr *atomic.Pointer[redactionRuntime]) *redactionRuntime {
	if cfg == nil || !cfg.Redaction.Enabled {
		return nil
	}
	configKey := redactionConfigKey(cfg)
	if ptr != nil {
		if rt := ptr.Load(); rt != nil && rt.configKey == configKey {
			return rt
		}
	}
	return &redactionRuntime{
		limits:               cfg.Redaction.Limits.ToLimits(),
		allowlistUnparseable: append([]string(nil), cfg.Redaction.AllowlistUnparseable...),
		configKey:            configKey,
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
