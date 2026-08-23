// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import "time"

const defaultTaintSourceLimit = 10

const (
	taintUnknownLabel      = "unknown"
	taintProfileStrict     = "strict"
	taintProfilePermissive = "permissive"
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
	TaintOriginAt    time.Time        `json:"taint_origin_at,omitempty"`
	TaintOriginURL   string           `json:"taint_origin_url,omitempty"`
	TaintOriginKind  string           `json:"taint_origin_kind,omitempty"`
	PromptHit        bool             `json:"prompt_hit"`
	MediaSeen        bool             `json:"media_seen"`
	ApprovedUntil    time.Time        `json:"approved_until,omitempty"`
	Sources          []TaintSourceRef `json:"sources,omitempty"`

	// TaintOriginAmbiguous records that more than one distinct source is
	// responsible for the session's escalating taint, so no single source may
	// be named as the origin. It is a security marker rather than a display
	// field: it is what keeps a cleared origin identity from reading as "no
	// origin was ever resolved" and falling back to the latest source.
	TaintOriginAmbiguous bool `json:"taint_origin_ambiguous,omitempty"`
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

	previousLevel := sr.Level
	if !sr.hasTaintOrigin() && previousLevel >= TaintAllowlistedReference {
		// Snapshot written before taint origins were tracked separately: the
		// level-establishing source survives only in LastExternal*, which the
		// update below is about to overwrite with this (possibly lower-risk)
		// source. Recover it before that happens.
		sr.TaintOriginAt = sr.LastExternalAt
		sr.TaintOriginURL = sr.LastExternalURL
		sr.TaintOriginKind = sr.LastExternalKind
		if !sr.hasTaintOrigin() {
			// Nothing recoverable. Record the origin as resolved but
			// unnameable, which is the same thing an ambiguous origin means to
			// every consumer: SecurityOrigin* report nothing, no source-scoped
			// override can match, and a repeat of this recovery on a later
			// call cannot adopt a benign later source instead.
			sr.markOriginAmbiguous()
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
	sr.updateTaintOrigin(source, previousLevel)

	if source.URL != "" || source.Kind != "" || source.Level != TaintTrusted {
		limit := observation.MaxSources
		if limit <= 0 {
			limit = defaultTaintSourceLimit
		}
		sr.Sources = appendBoundedSource(sr.Sources, source, limit)
	}
}

// updateTaintOrigin maintains the sticky source attribution consumed by trust
// decisions. The origin names the source responsible for the session's current
// taint, and it is deliberately not the latest source: that stickiness is what
// stops a later benign source from standing in for the one that actually
// tainted the session.
//
// Relative severity does not decide the origin once the escalation floor is in
// play. A source at or above that floor justifies escalation on its own for the
// rest of the session, so it is never retired by a later source - not by a more
// severe one, not by an equal one, and not by a weaker one. All three orderings
// fail open if severity is allowed to decide:
//
//   - Higher wins: a trusted docs page whose security prose trips the injection
//     patterns escalates the session from untrusted to hostile. If it takes the
//     origin, a source-scoped override naming that docs page clears an action
//     the earlier untrusted page still justifies blocking - and does so at a
//     strictly higher risk level, turning a block into an allow.
//   - Equal wins: there is no safe winner. First-to-arrive fails open when the
//     operator-trusted source arrives first; newest fails open in the other
//     order.
//   - Weaker loses: an untrusted page fetched after a hostile one still
//     contaminates independently, so leaving the hostile origin named lets an
//     override for it clear an action the untrusted page justifies blocking.
//
// So any second, distinct source at or above the floor marks the origin
// ambiguous: SecurityOrigin* then report nothing, no single-source override can
// match, and the full source list still carries every ref as evidence. A
// distinct source below the floor cannot escalate anything by itself, so it
// neither displaces an escalating origin nor creates ambiguity with one.
func (sr *SessionRisk) updateTaintOrigin(source TaintSourceRef, previousLevel TaintLevel) {
	if source.Level < TaintAllowlistedReference {
		return
	}
	if source.Kind == TaintSourceKindCrossAgent {
		// Synthesized from the current origin rather than ingested, so it is
		// never a second source and never names or unnames one. It must still
		// leave an origin resolved if it raised the level, or the legacy
		// recovery in Observe would adopt a later benign source on the next
		// observation. Unreachable from the only production caller, which
		// propagates an already contaminated session's own level.
		if source.Level > previousLevel {
			sr.markOriginAmbiguous()
		}
		return
	}
	if !sr.TaintOriginAmbiguous && source.URL == sr.TaintOriginURL && source.Kind == sr.TaintOriginKind {
		// The same source again, possibly at a higher level than before. Not a
		// second source, so the identity stands.
		if source.Level > previousLevel {
			sr.TaintOriginAt = source.Timestamp.UTC()
		}
		return
	}
	// Distinct from the recorded origin from here on.
	if taintLevelEscalates(previousLevel) {
		// The established origin escalates on its own and cannot be retired. A
		// second escalating source makes attribution ambiguous; a weaker one
		// changes nothing.
		if taintLevelEscalates(source.Level) {
			sr.markOriginAmbiguous()
		}
		return
	}
	if source.Level > previousLevel {
		sr.TaintOriginAt = source.Timestamp.UTC()
		sr.TaintOriginURL = source.URL
		sr.TaintOriginKind = source.Kind
		// Any earlier ambiguity was between sources below the escalation floor,
		// none of which an override needs to cover. Clearing it here is what
		// keeps two harmless reference fetches from making the session
		// permanently override-proof.
		sr.TaintOriginAmbiguous = false
		return
	}
	sr.markOriginAmbiguous()
}

// markOriginAmbiguous records that no single source may be named as the origin.
//
// Clearing the identity fields alone is not sufficient. hasTaintOrigin also
// consults TaintOriginAt, and an origin recovered from a legacy snapshot can
// carry an empty LastExternalAt alongside a URL. Clearing URL and Kind against
// a zero timestamp would make hasTaintOrigin report "no origin at all", and
// SecurityOrigin* would fall back to LastExternal* - which Observe has just
// overwritten with the newest source. The explicit flag is what keeps the
// ambiguous state from silently becoming unambiguous again.
func (sr *SessionRisk) markOriginAmbiguous() {
	sr.TaintOriginAmbiguous = true
	sr.TaintOriginURL = ""
	sr.TaintOriginKind = ""
}

// taintLevelEscalates reports whether a level can, on its own, drive a policy
// escalation. Shared by the policy matrix and the taint-origin ambiguity rule
// so the level at which an origin becomes irreplaceable cannot drift away from
// the level at which the matrix starts escalating.
func taintLevelEscalates(level TaintLevel) bool {
	return level >= TaintExternalUntrusted
}

// hasTaintOrigin reports whether a taint origin has been resolved for the
// current sticky level. Any one field is sufficient, and all of them must be
// consulted. An MCP tool result taints with a Kind and no URL, so keying on
// TaintOriginURL alone would treat a real origin as absent and fall back to the
// latest source - reintroducing exactly the substitution the origin exists to
// prevent. An ambiguous origin has no URL and no Kind by construction, so it
// depends on the flag for the same reason.
func (sr SessionRisk) hasTaintOrigin() bool {
	return sr.TaintOriginAmbiguous || !sr.TaintOriginAt.IsZero() ||
		sr.TaintOriginURL != "" || sr.TaintOriginKind != ""
}

// SecurityOriginURL returns the source that established the current taint
// level. The fallback preserves snapshots written before taint origins were
// tracked separately, and applies only when no origin was resolved at all.
func (sr SessionRisk) SecurityOriginURL() string {
	if sr.hasTaintOrigin() {
		return sr.TaintOriginURL
	}
	return sr.LastExternalURL
}

// SecurityOriginKind returns the kind paired with SecurityOriginURL.
func (sr SessionRisk) SecurityOriginKind() string {
	if sr.hasTaintOrigin() {
		return sr.TaintOriginKind
	}
	return sr.LastExternalKind
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

// PolicyEvaluateOptions carries optional fail-safe classification state.
type PolicyEvaluateOptions struct {
	FailSafeClassification  bool
	ClassificationConfident bool
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
	return pm.EvaluateWithOptions(taint, action, sensitivity, authority, PolicyEvaluateOptions{ClassificationConfident: true})
}

// EvaluateWithOptions applies the taint policy matrix with classifier
// confidence metadata.
func (pm PolicyMatrix) EvaluateWithOptions(
	taint TaintLevel,
	action ActionClass,
	sensitivity ActionSensitivity,
	authority AuthorityKind,
	opts PolicyEvaluateOptions,
) PolicyDecisionResult {
	if isAlwaysAllowedAction(action) && (!opts.FailSafeClassification || opts.ClassificationConfident) {
		return PolicyDecisionResult{Decision: PolicyAllow, Reason: "taint_safe_read_only_action"}
	}

	if !taintLevelEscalates(taint) {
		return PolicyDecisionResult{Decision: PolicyAllow, Reason: "trusted_or_allowlisted_context"}
	}

	if pm.profileMode() == taintProfilePermissive {
		return PolicyDecisionResult{Decision: PolicyAllow, Reason: "taint_permissive_observe_only"}
	}

	if taint >= TaintExternalHostile && isSensitiveAction(action, sensitivity) {
		return PolicyDecisionResult{Decision: PolicyBlock, Reason: "sensitive_action_after_hostile_external_exposure"}
	}

	// Fail-safe classification (opt-in): a read/browse/summarize that only
	// reached SensitivityProtected because it could NOT be confidently
	// classified must not fall through to allow under untrusted exposure.
	// Skipping the always-allow shortcut above is not enough: the untrusted
	// switch has no read-class branch, so escalate to HITL here. Fires only
	// when the toggle is on AND the classification was low-confidence, so
	// confidently-normal reads are unaffected (regression-safe when off).
	if opts.FailSafeClassification && !opts.ClassificationConfident &&
		sensitivity >= SensitivityProtected && isAlwaysAllowedAction(action) {
		return PolicyDecisionResult{Decision: PolicyAsk, Reason: "fail_safe_low_confidence_read_after_untrusted_exposure"}
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
	case taintProfilePermissive:
		return taintProfilePermissive
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
