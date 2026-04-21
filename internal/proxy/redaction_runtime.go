// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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
	}, nil
}

// RedactionRuntimePtr returns the atomic pointer to the redaction runtime
// snapshot. Reverse-proxy handlers use this to receive hot-reload updates
// without reconstructing policy from multiple atomics.
func (p *Proxy) RedactionRuntimePtr() *atomic.Pointer[redactionRuntime] {
	return &p.redactionRuntimePtr
}

func (p *Proxy) currentRedactionRuntime() *redactionRuntime {
	return p.redactionRuntimePtr.Load()
}

func applyBodyScanRedaction(req *BodyScanRequest, rt *redactionRuntime) {
	if req == nil || rt == nil {
		return
	}
	req.RedactMatcher = rt.matcher
	req.RedactLimits = rt.limits
	req.RedactAllowlistUnparseable = rt.allowlistUnparseable
}
