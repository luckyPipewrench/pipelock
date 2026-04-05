// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package receipt implements typed action records and self-signed receipts
// for every proxy decision. Each mediated action gets an action type, authority
// context, and an Ed25519-signed receipt emitted to the flight recorder.
package receipt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// NewActionID generates a random UUID v4 for action records.
func NewActionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal in a security context.
		// Fall back to zero UUID rather than panicking on the hot path.
		return "00000000-0000-4000-8000-000000000000"
	}
	// Set version 4 (bits 76-79 of byte 6).
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (bits 70-71 of byte 8).
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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
	ActionID   string     `json:"action_id"`
	ActionType ActionType `json:"action_type"`
	Timestamp  time.Time  `json:"timestamp"`

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

	// Transport context
	Transport string `json:"transport"`
	Method    string `json:"method,omitempty"`
	Layer     string `json:"layer,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
	RequestID string `json:"request_id,omitempty"`

	// Jurisdictional fields — present in schema for forward compatibility.
	// Empty in v1; populated when jurisdiction engine ships.
	Venue              string   `json:"venue,omitempty"`
	Jurisdiction       string   `json:"jurisdiction,omitempty"`
	RulebookID         string   `json:"rulebook_id,omitempty"`
	RemedyClass        string   `json:"remedy_class,omitempty"`
	ContestationWindow string   `json:"contestation_window,omitempty"`
	PrecedentRefs      []string `json:"precedent_refs,omitempty"`
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

// Canonical returns the deterministic JSON encoding of the action record.
// Used as the signing input for receipts. Fields are marshalled in Go's
// default struct-tag order, which is stable across runs.
func (ar ActionRecord) Canonical() ([]byte, error) {
	return json.Marshal(ar)
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
}

// NormalizeVerdict converts a config.Action* constant to a stable verdict string.
// Unknown verdicts pass through unchanged.
func NormalizeVerdict(verdict string) string {
	if mapped, ok := verdictMap[verdict]; ok {
		return mapped
	}
	return verdict
}
