// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package receipt implements typed action records and self-signed receipts
// for every proxy decision. Each mediated action gets an action type, authority
// context, and an Ed25519-signed receipt emitted to the flight recorder.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	DecisionPhaseDefer      = "defer"
	DecisionPhaseResolution = "resolution"
)

// NewActionID generates a UUIDv7 for action records. UUIDv7 is time-ordered
// (millisecond precision in the high bits) and globally unique, suitable for
// correlation handles in mediation envelopes and receipt lookups.
func NewActionID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return "00000000-0000-7000-8000-000000000000"
	}
	return id.String()
}

// ActionType classifies what kind of operation a mediated action represents.
// Every proxy decision is assigned one of these types based on request metadata.
type ActionType string

const (
	// ActionRead retrieves data without mutation (e.g., HTTP GET, web fetch).
	ActionRead ActionType = "read"
	// ActionDerive transforms data into new output (e.g., summarize, classify).
	ActionDerive ActionType = "derive"
	// ActionWrite mutates external state (e.g., HTTP POST/PUT/PATCH/DELETE, file write).
	ActionWrite ActionType = "write"
	// ActionDelegate grants authority to another actor (e.g., spawn sub-agent).
	ActionDelegate ActionType = "delegate"
	// ActionAuthorize approves a pending action (e.g., HITL confirm).
	ActionAuthorize ActionType = "authorize"
	// ActionSpend commits financial or metered resources (e.g., API billing).
	ActionSpend ActionType = "spend"
	// ActionCommit finalizes an irreversible side effect (e.g., payment, deploy).
	ActionCommit ActionType = "commit"
	// ActionActuate causes physical-world change (e.g., robot movement, IoT).
	ActionActuate ActionType = "actuate"
	// ActionUnclassified is for events that cannot be typed. High-risk by definition.
	ActionUnclassified ActionType = "unclassified"
)

// allActionTypes is the authoritative set of valid action types. Order matches
// the canonical action model in vision.md.
var allActionTypes = map[ActionType]bool{
	ActionRead:         true,
	ActionDerive:       true,
	ActionWrite:        true,
	ActionDelegate:     true,
	ActionAuthorize:    true,
	ActionSpend:        true,
	ActionCommit:       true,
	ActionActuate:      true,
	ActionUnclassified: true,
}

// ValidActionType reports whether t is a recognized action type.
func ValidActionType(t ActionType) bool {
	return allActionTypes[t]
}

// SideEffectClass describes the external impact of an action.
type SideEffectClass string

const (
	SideEffectNone          SideEffectClass = "none"
	SideEffectExternalRead  SideEffectClass = "external_read"
	SideEffectExternalWrite SideEffectClass = "external_write"
	SideEffectFinancial     SideEffectClass = "financial"
	SideEffectPhysical      SideEffectClass = "physical"
)

// Reversibility describes whether an action can be undone.
type Reversibility string

const (
	ReversibilityFull          Reversibility = "full"
	ReversibilityCompensatable Reversibility = "compensatable"
	ReversibilityIrreversible  Reversibility = "irreversible"
	ReversibilityUnknown       Reversibility = "unknown"
)

// ActionRecordVersion is the schema version for action records.
// Verifiers MUST reject records with unknown versions.
const ActionRecordVersion = 1

// ActionRecord is a typed, attributed record of a single mediated action.
// Emitted for HTTP proxy decisions (fetch, forward, CONNECT) and MCP tool
// call decisions when a signing key is configured. Schema aligns with the
// Canonical Action Model in vision.md.
type ActionRecord struct {
	// Schema
	Version int `json:"version"`

	// Identity
	ActionID       string     `json:"action_id"`
	ParentActionID string     `json:"parent_action_id,omitempty"`
	ActionType     ActionType `json:"action_type"`
	Timestamp      time.Time  `json:"timestamp"`

	// Authority context (minimal ledger fields)
	Principal       string   `json:"principal"`
	Actor           string   `json:"actor"`
	DelegationChain []string `json:"delegation_chain"`

	// Target
	Target string `json:"target"`

	// Semantics
	Intent         string   `json:"intent,omitempty"`
	DataClassesIn  []string `json:"data_classes_in,omitempty"`
	DataClassesOut []string `json:"data_classes_out,omitempty"`

	// Risk classification
	SideEffectClass SideEffectClass `json:"side_effect_class"`
	Reversibility   Reversibility   `json:"reversibility"`

	// Policy context
	PolicyHash string `json:"policy_hash"`
	Verdict    string `json:"verdict"`
	// Deferred-decision context.
	DecisionPhase     string `json:"decision_phase,omitempty"`
	DeferID           string `json:"defer_id,omitempty"`
	ResolutionPolicy  string `json:"resolution_policy,omitempty"`
	ResolutionSource  string `json:"resolution_source,omitempty"`
	SessionID         string `json:"session_id,omitempty"`
	SessionIDOriginal string `json:"session_id_original,omitempty"`
	// Taint-aware policy escalation context.
	SessionTaintLevel   string                   `json:"session_taint_level,omitempty"`
	SessionContaminated bool                     `json:"session_contaminated,omitempty"`
	RecentTaintSources  []session.TaintSourceRef `json:"recent_taint_sources,omitempty"`
	SessionTaskID       string                   `json:"session_task_id,omitempty"`
	SessionTaskLabel    string                   `json:"session_task_label,omitempty"`
	AuthorityKind       string                   `json:"authority_kind,omitempty"`
	TaintDecision       string                   `json:"taint_decision,omitempty"`
	TaintDecisionReason string                   `json:"taint_decision_reason,omitempty"`
	TaskOverrideApplied bool                     `json:"task_override_applied,omitempty"`

	// Contract context, populated when live lock evaluates this action.
	ContractWinningSource string   `json:"contract_winning_source,omitempty"`
	ContractLiveVerdict   string   `json:"contract_live_verdict,omitempty"`
	ContractPolicySources []string `json:"contract_policy_sources,omitempty"`
	ContractRuleID        string   `json:"contract_rule_id,omitempty"`
	ActiveManifestHash    string   `json:"active_manifest_hash,omitempty"`
	ContractHash          string   `json:"contract_hash,omitempty"`
	ContractSelectorID    string   `json:"contract_selector_id,omitempty"`
	ContractGeneration    uint64   `json:"contract_generation,omitempty"`

	// Transport context
	Transport string            `json:"transport"`
	Method    string            `json:"method,omitempty"`
	Layer     string            `json:"layer,omitempty"`
	Pattern   string            `json:"pattern,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Redaction *RedactionSummary `json:"redaction,omitempty"`
	Shield    *ShieldSummary    `json:"shield,omitempty"`
	RequestID string            `json:"request_id,omitempty"`

	// Chain integrity - links receipts into a tamper-evident sequence.
	// ChainPrevHash is "genesis" for the first receipt in a session.
	ChainPrevHash string `json:"chain_prev_hash"`
	ChainSeq      uint64 `json:"chain_seq"`

	// RunNonce is generated once per process run and bound into every signed
	// action record emitted by that process. Legacy receipts omit it; verifiers
	// canonicalize absence the same as the Go omitempty zero value.
	RunNonce string `json:"run_nonce,omitempty"`

	// KeyTransition is present ONLY on the first receipt of a new chain
	// segment that begins after a legitimate signing-key rotation. It binds
	// the new segment to the prior segment's tail (prior signer key, final
	// seq, and tail hash) so the segment boundary is auditable and the
	// transition is provable from the evidence file alone. Absent (nil) on
	// every other receipt. See receipt/emitter.go resumeChain for the trust
	// model: the new segment's ChainPrevHash equals the prior tail's hash,
	// and the recorder's outer hash chain remains the cross-segment
	// tamper-evidence layer.
	KeyTransition *KeyTransition `json:"key_transition,omitempty"`

	// Jurisdictional fields - present in schema for forward compatibility.
	// Empty in v1; populated when jurisdiction engine ships.
	Venue              string   `json:"venue,omitempty"`
	Jurisdiction       string   `json:"jurisdiction,omitempty"`
	RulebookID         string   `json:"rulebook_id,omitempty"`
	RemedyClass        string   `json:"remedy_class,omitempty"`
	ContestationWindow string   `json:"contestation_window,omitempty"`
	PrecedentRefs      []string `json:"precedent_refs,omitempty"`
}

// KeyTransition records the boundary between two chain segments signed by
// different keys. It is stamped on the first receipt of the new segment after a
// legitimate signing-key rotation, binding that segment to the prior segment's
// tail. A verifier walking the segments can confirm the new segment was
// intentionally anchored to the prior tail (PriorChainHash) rather than forked.
// The signing key itself rotates as an operator action; this marker makes the
// rotation visible in-band, while the recorder's outer hash chain provides the
// authoritative cross-segment tamper-evidence.
type KeyTransition struct {
	// PriorSignerKey is the hex-encoded public key that signed the prior
	// segment's tail receipt.
	PriorSignerKey string `json:"prior_signer_key"`
	// PriorChainSeq is the chain_seq of the prior segment's tail receipt.
	PriorChainSeq uint64 `json:"prior_chain_seq"`
	// PriorChainHash is the receipt hash of the prior segment's tail. This
	// equals the new segment's first-receipt ChainPrevHash, linking the two
	// segments.
	PriorChainHash string `json:"prior_chain_hash"`
}

// RedactionSummary captures the request-side redaction outcome for a mediated
// action. Present only when redaction actually replaced one or more values.
type RedactionSummary struct {
	Profile           string         `json:"profile,omitempty"`
	Provider          string         `json:"provider,omitempty"`
	Parser            string         `json:"parser,omitempty"`
	TotalRedactions   int            `json:"total_redactions,omitempty"`
	ByClass           map[string]int `json:"by_class,omitempty"`
	CacheBoundaryKept bool           `json:"cache_boundary_kept,omitempty"`
}

// ShieldSummary captures Browser Shield response-side rewrites for an allowed
// response. Present only when the shield actually changed browser-visible
// content.
type ShieldSummary struct {
	Pipeline                 string `json:"pipeline,omitempty"`
	TotalRewrites            int    `json:"total_rewrites,omitempty"`
	ExtensionProbes          int    `json:"extension_probes,omitempty"`
	TrackingBeacons          int    `json:"tracking_beacons,omitempty"`
	AgentTraps               int    `json:"agent_traps,omitempty"`
	FingerprintShimInjected  bool   `json:"fingerprint_shim_injected,omitempty"`
	SVGForeignObjects        int    `json:"svg_foreign_objects,omitempty"`
	SVGEventHandlers         int    `json:"svg_event_handlers,omitempty"`
	SVGExternalReferences    int    `json:"svg_external_references,omitempty"`
	SVGHiddenText            int    `json:"svg_hidden_text,omitempty"`
	SVGAnimationInjections   int    `json:"svg_animation_injections,omitempty"`
	BodyBytes                int    `json:"body_bytes,omitempty"`
	ScannedBytes             int    `json:"scanned_bytes,omitempty"`
	Partial                  bool   `json:"partial,omitempty"`
	AdaptiveSignalsRecorded  int    `json:"adaptive_signals_recorded,omitempty"`
	AdaptiveSignalMaxPerBody int    `json:"adaptive_signal_max_per_body,omitempty"`
}

// Validate checks that required fields are populated and the action type is valid.
func (ar ActionRecord) Validate() error {
	if ar.Version != ActionRecordVersion {
		return fmt.Errorf("unsupported action record version %d (expected %d)", ar.Version, ActionRecordVersion)
	}
	if ar.ActionID == "" {
		return fmt.Errorf("action_id is required")
	}
	if !ValidActionType(ar.ActionType) {
		return fmt.Errorf("invalid action_type %q", ar.ActionType)
	}
	if ar.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if ar.Target == "" {
		return fmt.Errorf("target is required")
	}
	if ar.Verdict == "" {
		return fmt.Errorf("verdict is required")
	}
	if ar.Transport == "" {
		return fmt.Errorf("transport is required")
	}
	return nil
}

// Canonical returns the deterministic JSON encoding for the action record's
// declared schema version. It is the signing input used by receipts.
func (ar ActionRecord) Canonical() ([]byte, error) {
	return canonicalActionRecord(ar.Version, ar)
}

// Hash returns the SHA-256 hex digest of the canonical JSON encoding.
func (ar ActionRecord) Hash() (string, error) {
	data, err := ar.Canonical()
	if err != nil {
		return "", fmt.Errorf("canonical encoding: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// VerdictToAction maps a pipelock verdict string (from config.Action* constants)
// to a human-readable verdict for the action record.
var verdictMap = map[string]string{
	config.ActionBlock:   "block",
	config.ActionAllow:   "allow",
	config.ActionWarn:    "warn",
	config.ActionAsk:     "ask",
	config.ActionStrip:   "strip",
	config.ActionForward: "forward",
	config.ActionDefer:   "defer",
}

// NormalizeVerdict converts a config.Action* constant to a stable verdict string.
// Unknown verdicts pass through unchanged.
func NormalizeVerdict(verdict string) string {
	if mapped, ok := verdictMap[verdict]; ok {
		return mapped
	}
	return verdict
}
