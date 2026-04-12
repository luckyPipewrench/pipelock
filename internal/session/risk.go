// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import "time"

const defaultTaintSourceLimit = 10

const (
	taintUnknownLabel  = "unknown"
	taintProfileStrict = "strict"
)

// TaintLevel describes the trust level of content recently observed by a
// session. Higher values are less trusted.
type TaintLevel uint8

const (
	TaintTrusted TaintLevel = iota
	TaintInternalGenerated
	TaintAllowlistedReference
	TaintExternalLowRisk
	TaintExternalUntrusted
	TaintExternalHostile
)

// ActionClass describes the high-level action being evaluated by taint policy.
type ActionClass uint8

const (
	ActionClassRead ActionClass = iota
	ActionClassBrowse
	ActionClassSummarize
	ActionClassWrite
	ActionClassExec
	ActionClassSecret
	ActionClassPublish
	ActionClassNetwork
)

// ActionSensitivity describes the sensitivity of a target object/action.
type ActionSensitivity uint8

const (
	SensitivityNormal ActionSensitivity = iota
	SensitivityElevated
	SensitivityProtected
)

// AuthorityKind describes how strongly an action is authorized. Larger values
// are stronger authority and can satisfy stronger policy thresholds.
type AuthorityKind uint8

const (
	AuthorityUnknown AuthorityKind = iota
	AuthorityExternal
	AuthorityPolicy
	AuthorityUserBroad
	AuthorityUserExact
	AuthorityOperatorOverride
)

// PolicyDecision is the taint policy result for an action.
type PolicyDecision uint8

const (
	PolicyAllow PolicyDecision = iota
	PolicyWarn
	PolicyAsk
	PolicyBlock
)

// TaintSourceRef records a recent source that influenced session taint.
type TaintSourceRef struct {
	URL         string     `json:"url"`
	Kind        string     `json:"kind"`
	Level       TaintLevel `json:"level"`
	Timestamp   time.Time  `json:"timestamp"`
	ReceiptID   string     `json:"receipt_id,omitempty"`
	MatchReason string     `json:"match_reason,omitempty"`
}

// SessionRisk is the taint-aware risk state attached to a live session.
type SessionRisk struct {
	Level            TaintLevel       `json:"level"`
	Contaminated     bool             `json:"contaminated"`
	LastExternalAt   time.Time        `json:"last_external_at,omitempty"`
	LastExternalURL  string           `json:"last_external_url,omitempty"`
	LastExternalKind string           `json:"last_external_kind,omitempty"`
	PromptHit        bool             `json:"prompt_hit"`
	MediaSeen        bool             `json:"media_seen"`
	ApprovedUntil    time.Time        `json:"approved_until,omitempty"`
	Sources          []TaintSourceRef `json:"sources,omitempty"`
}

// Snapshot returns a copy that is safe to hand to callers.
func (sr SessionRisk) Snapshot() SessionRisk {
	if len(sr.Sources) > 0 {
		sr.Sources = append([]TaintSourceRef(nil), sr.Sources...)
	}
	return sr
}

// Observe folds a new risk observation into the session's sticky taint state.
func (sr *SessionRisk) Observe(observation RiskObservation) {
	if sr == nil {
		return
	}

	source := observation.Source
	if source.Timestamp.IsZero() {
		source.Timestamp = time.Now().UTC()
	}

	if observation.PromptHit {
		source.Level = maxTaintLevel(source.Level, TaintExternalHostile)
		if source.MatchReason == "" {
			source.MatchReason = "prompt_injection_pattern"
		}
	}

	sr.Level = maxTaintLevel(sr.Level, source.Level)
	sr.PromptHit = sr.PromptHit || observation.PromptHit
	sr.MediaSeen = sr.MediaSeen || observation.MediaSeen

	if !observation.ApprovedUntil.IsZero() && observation.ApprovedUntil.After(sr.ApprovedUntil) {
		sr.ApprovedUntil = observation.ApprovedUntil.UTC()
	}

	if source.Level >= TaintExternalUntrusted {
		sr.Contaminated = true
	}

	if source.Level >= TaintAllowlistedReference {
		sr.LastExternalAt = source.Timestamp.UTC()
		sr.LastExternalURL = source.URL
		sr.LastExternalKind = source.Kind
	}

	if source.URL != "" || source.Kind != "" || source.Level != TaintTrusted {
		limit := observation.MaxSources
		if limit <= 0 {
			limit = defaultTaintSourceLimit
		}
		sr.Sources = appendBoundedSource(sr.Sources, source, limit)
	}
}

// RiskObservation describes a single taint observation flowing into a session.
type RiskObservation struct {
	Source        TaintSourceRef
	MediaSeen     bool
	PromptHit     bool
	MaxSources    int
	ApprovedUntil time.Time
}

// TrustOverride grants a narrow, expiring trust exemption.
type TrustOverride struct {
	Scope       string
	TaskID      string
	SourceMatch string
	ActionMatch string
	ExpiresAt   time.Time
	GrantedBy   string
	Reason      string
}

// PolicyMatrix controls the conservative taint escalation profile.
type PolicyMatrix struct {
	Profile string
}

// PolicyDecisionResult carries the decision plus a stable machine reason.
type PolicyDecisionResult struct {
	Decision PolicyDecision
	Reason   string
}

// RiskState is implemented by session recorders that track taint state.
type RiskState interface {
	RiskSnapshot() SessionRisk
	ObserveRisk(observation RiskObservation)
}

// String returns the stable wire label for a taint level.
func (t TaintLevel) String() string {
	switch t {
	case TaintTrusted:
		return "trusted"
	case TaintInternalGenerated:
		return "internal_generated"
	case TaintAllowlistedReference:
		return "allowlisted_reference"
	case TaintExternalLowRisk:
		return "external_low_risk"
	case TaintExternalUntrusted:
		return "external_untrusted"
	case TaintExternalHostile:
		return "external_hostile"
	default:
		return taintUnknownLabel
	}
}

// String returns the stable wire label for an action class.
func (a ActionClass) String() string {
	switch a {
	case ActionClassRead:
		return "read"
	case ActionClassBrowse:
		return "browse"
	case ActionClassSummarize:
		return "summarize"
	case ActionClassWrite:
		return "write"
	case ActionClassExec:
		return "exec"
	case ActionClassSecret:
		return "secret"
	case ActionClassPublish:
		return "publish"
	case ActionClassNetwork:
		return "network"
	default:
		return taintUnknownLabel
	}
}

// String returns the stable wire label for action sensitivity.
func (s ActionSensitivity) String() string {
	switch s {
	case SensitivityNormal:
		return "normal"
	case SensitivityElevated:
		return "elevated"
	case SensitivityProtected:
		return "protected"
	default:
		return taintUnknownLabel
	}
}

// String returns the stable wire label for an authority kind.
func (a AuthorityKind) String() string {
	switch a {
	case AuthorityUnknown:
		return "unknown"
	case AuthorityExternal:
		return "external"
	case AuthorityPolicy:
		return "policy"
	case AuthorityUserBroad:
		return "user_broad"
	case AuthorityUserExact:
		return "user_exact"
	case AuthorityOperatorOverride:
		return "operator_override"
	default:
		return taintUnknownLabel
	}
}

// String returns the stable wire label for a policy decision.
func (d PolicyDecision) String() string {
	switch d {
	case PolicyAllow:
		return "allow"
	case PolicyWarn:
		return "warn"
	case PolicyAsk:
		return "ask"
	case PolicyBlock:
		return "block"
	default:
		return taintUnknownLabel
	}
}

// Evaluate applies the taint policy matrix for the configured profile.
func (pm PolicyMatrix) Evaluate(
	taint TaintLevel,
	action ActionClass,
	sensitivity ActionSensitivity,
	authority AuthorityKind,
) PolicyDecisionResult {
	if isAlwaysAllowedAction(action) {
		return PolicyDecisionResult{Decision: PolicyAllow, Reason: "taint_safe_read_only_action"}
	}

	if taint < TaintExternalUntrusted {
		return PolicyDecisionResult{Decision: PolicyAllow, Reason: "trusted_or_allowlisted_context"}
	}

	if taint >= TaintExternalHostile && isSensitiveAction(action, sensitivity) {
		return PolicyDecisionResult{Decision: PolicyBlock, Reason: "sensitive_action_after_hostile_external_exposure"}
	}

	switch action {
	case ActionClassWrite:
		if sensitivity >= SensitivityProtected && authority < AuthorityUserExact {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "protected_write_after_untrusted_external_exposure"}
		}
		if pm.profileMode() == taintProfileStrict && sensitivity >= SensitivityElevated && authority < AuthorityUserExact {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "elevated_write_after_untrusted_external_exposure"}
		}
	case ActionClassExec:
		if authority < AuthorityOperatorOverride {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "mutating_exec_after_untrusted_external_exposure"}
		}
	case ActionClassSecret:
		if authority < AuthorityUserExact {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "secret_use_after_untrusted_external_exposure"}
		}
	case ActionClassPublish:
		if authority < AuthorityUserExact {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "external_publish_after_untrusted_external_exposure"}
		}
	case ActionClassNetwork:
		if pm.profileMode() == taintProfileStrict && sensitivity >= SensitivityElevated && authority < AuthorityUserExact {
			return PolicyDecisionResult{Decision: PolicyAsk, Reason: "mutating_network_after_untrusted_external_exposure"}
		}
	}

	return PolicyDecisionResult{Decision: PolicyAllow, Reason: "no_taint_escalation_required"}
}

func (pm PolicyMatrix) profileMode() string {
	switch pm.Profile {
	case taintProfileStrict:
		return taintProfileStrict
	case "permissive":
		return "permissive"
	default:
		return "balanced"
	}
}

func isAlwaysAllowedAction(action ActionClass) bool {
	return action == ActionClassRead || action == ActionClassBrowse || action == ActionClassSummarize
}

func isSensitiveAction(action ActionClass, sensitivity ActionSensitivity) bool {
	if sensitivity >= SensitivityElevated {
		return true
	}
	switch action {
	case ActionClassWrite, ActionClassExec, ActionClassSecret, ActionClassPublish:
		return true
	default:
		return false
	}
}

func maxTaintLevel(a, b TaintLevel) TaintLevel {
	if b > a {
		return b
	}
	return a
}

func appendBoundedSource(sources []TaintSourceRef, source TaintSourceRef, limit int) []TaintSourceRef {
	sources = append(sources, source)
	if len(sources) <= limit {
		return sources
	}
	return append([]TaintSourceRef(nil), sources[len(sources)-limit:]...)
}
