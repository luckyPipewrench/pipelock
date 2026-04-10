// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	taintScopeAction = "action"
	taintScopeSource = "source"
)

type taintDecision struct {
	Risk        session.SessionRisk
	ActionClass session.ActionClass
	Sensitivity session.ActionSensitivity
	Authority   session.AuthorityKind
	Result      session.PolicyDecisionResult
	ActionRef   string
}

func observeHTTPResponseTaint(rec session.Recorder, cfg *config.Config, rawURL, contentType, kind string, promptHit bool) {
	rs, ok := rec.(session.RiskState)
	if !ok || cfg == nil || !cfg.Taint.Enabled {
		return
	}
	observation := session.ClassifyHTTPResponseObservation(rawURL, contentType, cfg.Taint.AllowlistedDomains, promptHit)
	observation.Source.Kind = kind
	observation.MaxSources = cfg.Taint.RecentSources
	rs.ObserveRisk(observation)
}

func evaluateHTTPTaint(cfg *config.Config, rec session.Recorder, method string, parsedURL *url.URL) taintDecision {
	decision := taintDecision{
		ActionClass: session.ActionClassRead,
		Sensitivity: session.SensitivityNormal,
		Authority:   session.AuthorityUserBroad,
		Result:      session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "taint_disabled"},
	}
	if cfg == nil || !cfg.Taint.Enabled || parsedURL == nil {
		return decision
	}

	if rs, ok := rec.(session.RiskState); ok {
		decision.Risk = rs.RiskSnapshot()
	}
	decision.ActionClass, decision.Sensitivity = session.ClassifyHTTPAction(method, parsedURL.Path, cfg.Taint.ProtectedPaths, cfg.Taint.ElevatedPaths)
	decision.ActionRef = httpActionRef(decision.ActionClass, method, parsedURL)
	decision.Result = session.PolicyMatrix{Profile: cfg.Taint.Policy}.Evaluate(
		decision.Risk.Level,
		decision.ActionClass,
		decision.Sensitivity,
		decision.Authority,
	)
	if trustOverrideApplies(cfg.Taint.TrustOverrides, decision.Risk, decision.ActionRef) {
		decision.Result = session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "taint_trust_override"}
	}
	return decision
}

func httpActionRef(action session.ActionClass, method string, parsedURL *url.URL) string {
	if parsedURL == nil {
		return strings.ToLower(fmt.Sprintf("%s:%s", action.String(), method))
	}
	return strings.ToLower(fmt.Sprintf("%s:%s:%s", action.String(), method, parsedURL.String()))
}

func trustOverrideApplies(overrides []config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	now := time.Now().UTC()
	for _, override := range overrides {
		if !override.ExpiresAt.IsZero() && override.ExpiresAt.Before(now) {
			continue
		}
		if !overrideMatches(override, risk, actionRef) {
			continue
		}
		return true
	}
	return false
}

func overrideMatches(override config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	switch override.Scope {
	case taintScopeAction:
		if override.ActionMatch == "" || !wildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		if override.SourceMatch != "" && !riskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		return true
	case taintScopeSource:
		if override.SourceMatch == "" || !riskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		if override.ActionMatch != "" && !wildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		return true
	default:
		return false
	}
}

func riskSourceMatches(risk session.SessionRisk, pattern string) bool {
	if wildcardMatch(risk.LastExternalURL, pattern) {
		return true
	}
	for _, source := range risk.Sources {
		if wildcardMatch(source.URL, pattern) {
			return true
		}
	}
	return false
}

func wildcardMatch(value, pattern string) bool {
	if value == "" || pattern == "" {
		return false
	}
	if matched, err := path.Match(pattern, value); err == nil && matched {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	if !strings.HasSuffix(pattern, "*") && parts[len(parts)-1] != "" && !strings.HasSuffix(value, parts[len(parts)-1]) {
		return false
	}
	return true
}
