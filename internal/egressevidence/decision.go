// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package egressevidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// ContractVersion versions these candidate typed facts independently of the
// signed receipt envelope. This model package does not register receipt kinds;
// the fixture-only signed adapter lives under internal/contract.
const ContractVersion = 1

const maxDecisionBytes = 16 * 1024

type Phase string

const (
	PhaseIntent  Phase = "intent"
	PhaseOutcome Phase = "outcome"
)

type FindingDisposition string

const (
	FindingBlock     FindingDisposition = "block"
	FindingRedact    FindingDisposition = "redact"
	FindingObserve   FindingDisposition = "observe"
	FindingAuthorize FindingDisposition = "authorize"
	FindingExempt    FindingDisposition = "exempt"
)

type PatternClass string

const (
	PatternCoreFloor  PatternClass = "core_floor"
	PatternConfigured PatternClass = "configured"
)

type ByteForm string

const (
	ByteFormNone        ByteForm = "none"
	ByteFormOriginal    ByteForm = "original"
	ByteFormTransformed ByteForm = "transformed"
	ByteFormUnknown     ByteForm = "unknown"
)

type Release string

const (
	ReleaseNone     Release = "none"
	ReleasePartial  Release = "partial"
	ReleaseComplete Release = "complete"
	ReleaseUnknown  Release = "unknown"
)

// Outcome records observed request-byte release, independently of the selected
// finding handling. Contradictions between intent and observation are valid
// evidence of an enforcement failure; validators must not erase that evidence.
type Outcome struct {
	Release  Release  `json:"release"`
	ByteForm ByteForm `json:"byte_form"`
}

type AuthorizationKind string

const (
	AuthorizationNone      AuthorizationKind = "none"
	AuthorizationPermit    AuthorizationKind = "authorization"
	AuthorizationExemption AuthorizationKind = "exemption"
)

type Authorization struct {
	Kind   AuthorizationKind `json:"kind"`
	Ref    string            `json:"ref,omitempty"`
	Origin PolicyOrigin      `json:"origin,omitempty"`
}

type PolicyOrigin string

const (
	PolicyOriginBuiltin  PolicyOrigin = "builtin"
	PolicyOriginOperator PolicyOrigin = "operator"
)

func (origin PolicyOrigin) valid() bool {
	return origin == PolicyOriginBuiltin || origin == PolicyOriginOperator
}

// RewriteFallbackReason is a candidate vocabulary, not a declaration that any
// production producer emits or covers these cases. Reasons without a verified
// producer remain reserved until the coordinated integration is implemented.
type RewriteFallbackReason string

const (
	RewriteUnparseableBody     RewriteFallbackReason = "unparseable_body"
	RewriteNoSafeRawSpan       RewriteFallbackReason = "no_safe_raw_span"
	RewriteUnsupportedEncoding RewriteFallbackReason = "unsupported_encoding"
	RewriteUnsupportedShape    RewriteFallbackReason = "unsupported_shape"
	RewriteOpaqueArguments     RewriteFallbackReason = "opaque_arguments"
)

// RewriteFallback records rewrite inability and the named policy consulted for
// that case. It is independent of effective finding handling and observed byte
// release, and grants no permission to forward. A future signing adapter must
// resolve this reference, and every named Authorization, against the effective
// policy before signing; structural validation cannot authenticate references.
type RewriteFallback struct {
	Reason       RewriteFallbackReason `json:"reason"`
	PolicyRef    string                `json:"policy_ref"`
	PolicyOrigin PolicyOrigin          `json:"policy_origin"`
}

func (f RewriteFallback) validate() error {
	if !slices.Contains([]RewriteFallbackReason{
		RewriteUnparseableBody, RewriteNoSafeRawSpan,
		RewriteUnsupportedEncoding, RewriteUnsupportedShape, RewriteOpaqueArguments,
	}, f.Reason) {
		return fmt.Errorf("invalid rewrite fallback reason")
	}
	if !validIdentifier(f.PolicyRef) || !f.PolicyOrigin.valid() {
		return fmt.Errorf("invalid rewrite fallback policy reference or origin")
	}
	return nil
}

type PersistencePolicy string

const (
	PersistenceRequired   PersistencePolicy = "required_before_action"
	PersistenceBestEffort PersistencePolicy = "best_effort"
)

type DestinationKind string

const (
	DestinationNetwork      DestinationKind = "network"
	DestinationLocalProcess DestinationKind = "local_process"
)

type DestinationRedactionReason string

const DestinationClassifiedSensitive DestinationRedactionReason = "classified_sensitive"

// DestinationRedaction records intentional omission of a sensitive destination
// reference. It neither identifies a shared destination nor implies missing
// collection coverage. Separate actions and decisions retain distinct IDs even
// when their destination references are omitted. The producer's privacy choice
// is detection-scoped, not a configured-destination allowlist; this model does
// not implement that classification or any runtime privacy setting.
type DestinationRedaction struct {
	Reason DestinationRedactionReason `json:"reason"`
}

// Decision holds candidate signable facts, not a durability acknowledgment.
// All IDs are producer/configuration references. No field accepts a sample,
// credential, header value, command line, URL, or hash of a secret value.
// Network references must be canonical hosts cleared by the producer's declared
// finding-aware evidence privacy policy. A validator cannot establish that
// provenance; withheld destination facts use the explicit redaction form.
type Decision struct {
	Version              int                   `json:"version"`
	ActionID             string                `json:"action_id"`
	DecisionID           string                `json:"decision_id"`
	SiteID               SiteID                `json:"site_id"`
	Plane                Plane                 `json:"plane"`
	Transport            Transport             `json:"transport"`
	Location             Location              `json:"location"`
	View                 View                  `json:"view"`
	Boundary             Boundary              `json:"boundary"`
	Phase                Phase                 `json:"phase"`
	DestinationKind      DestinationKind       `json:"destination_kind"`
	DestinationRef       string                `json:"destination_ref,omitempty"`
	DestinationRedaction *DestinationRedaction `json:"destination_redaction,omitempty"`
	PatternClass         PatternClass          `json:"pattern_class"`
	RuleID               string                `json:"rule_id"`
	FindingDisposition   FindingDisposition    `json:"finding_disposition"`
	PlannedByteForm      ByteForm              `json:"planned_byte_form"`
	Authorization        Authorization         `json:"authorization"`
	RewriteFallback      *RewriteFallback      `json:"rewrite_fallback,omitempty"`
	PersistencePolicy    PersistencePolicy     `json:"persistence_policy"`
	Outcome              *Outcome              `json:"outcome,omitempty"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// A numeric final label sends a host down IPv4 parsing in URL consumers. This
// classifies that syntax only; the shared destination parser remains the sole
// IP parser. Bare "0x" is included because its empty hex suffix is number-like.
var numericHostLastLabelPattern = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)

// ParseDecision is strict about duplicate/unknown fields, nulls and trailing
// data. Acceptance is structural only; it is not signature verification,
// registry membership, producer coverage, or durability confirmation.
func ParseDecision(raw []byte) (Decision, error) {
	if len(raw) == 0 || len(raw) > maxDecisionBytes {
		return Decision{}, fmt.Errorf("invalid evidence decision size")
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return Decision{}, fmt.Errorf("duplicate or malformed decision object")
	}
	if err := validateDecisionJSONShape(raw); err != nil {
		return Decision{}, err
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := tokens.Token()
		if err == io.EOF {
			break
		}
		if err != nil || token == nil {
			return Decision{}, fmt.Errorf("null or malformed evidence decision")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decision Decision
	if err := decoder.Decode(&decision); err != nil {
		return Decision{}, fmt.Errorf("invalid evidence decision fields")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Decision{}, fmt.Errorf("trailing evidence decision data")
	}
	if err := decision.Validate(); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// Validate checks the shape of recorded assertions, not policy eligibility.
// Finding class and selected handling alone cannot establish compliance or a
// contradiction: core findings may be removed by redaction and a clean rescan,
// while pre-transform observe evidence may retain that original finding.
// Named built-in credential audiences may also authorize original bytes.
// Assessment needs site view, handling, authority and residual/release context. A
// successful validation never grants permission to release bytes; existing
// scanner enforcement remains responsible for the immutable floor.
func (d Decision) Validate() error {
	if d.Version != ContractVersion {
		return fmt.Errorf("unsupported evidence decision version")
	}
	if !uuidPattern.MatchString(d.ActionID) || !uuidPattern.MatchString(d.DecisionID) || d.ActionID == d.DecisionID {
		return fmt.Errorf("invalid or aliased action and decision IDs")
	}
	if err := d.site().Validate(); err != nil {
		return err
	}
	if d.Plane != PlaneProxy {
		return fmt.Errorf("initial evidence contract covers only proxy sites")
	}
	if !validIdentifier(d.RuleID) {
		return fmt.Errorf("invalid evidence rule reference")
	}
	if d.PatternClass != PatternCoreFloor && d.PatternClass != PatternConfigured {
		return fmt.Errorf("invalid evidence pattern class")
	}
	if (d.DestinationRef != "") == (d.DestinationRedaction != nil) {
		return fmt.Errorf("evidence destination requires exactly one reference or redaction")
	}
	if d.DestinationRedaction != nil && d.DestinationRedaction.Reason != DestinationClassifiedSensitive {
		return fmt.Errorf("invalid evidence destination redaction reason")
	}
	switch d.DestinationKind {
	case DestinationNetwork:
		if d.Transport == TransportMCPStdio || (d.DestinationRedaction == nil && !canonicalHost(d.DestinationRef)) {
			return fmt.Errorf("invalid canonical network destination")
		}
	case DestinationLocalProcess:
		if d.Transport != TransportMCPStdio || (d.DestinationRedaction == nil && !validIdentifier(d.DestinationRef)) {
			return fmt.Errorf("invalid local process reference")
		}
	default:
		return fmt.Errorf("invalid evidence destination kind")
	}
	if !slices.Contains([]ByteForm{ByteFormNone, ByteFormOriginal, ByteFormTransformed}, d.PlannedByteForm) {
		return fmt.Errorf("invalid planned byte form")
	}
	if err := d.validateFinding(); err != nil {
		return err
	}
	if d.RewriteFallback != nil {
		if err := d.RewriteFallback.validate(); err != nil {
			return err
		}
	}
	if d.PersistencePolicy != PersistenceRequired && d.PersistencePolicy != PersistenceBestEffort {
		return fmt.Errorf("invalid evidence persistence policy")
	}
	switch d.Phase {
	case PhaseIntent:
		if d.Outcome != nil {
			return fmt.Errorf("intent cannot contain observed byte outcome")
		}
	case PhaseOutcome:
		if d.Outcome == nil {
			return fmt.Errorf("outcome observation is missing")
		}
		if err := d.Outcome.validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid evidence phase")
	}
	return nil
}

func (d Decision) validateFinding() error {
	expected := AuthorizationNone
	switch d.FindingDisposition {
	case FindingBlock:
		if d.PlannedByteForm != ByteFormNone {
			return fmt.Errorf("block intent cannot plan byte release")
		}
	case FindingRedact:
		if d.PlannedByteForm == ByteFormOriginal {
			return fmt.Errorf("redact intent cannot plan original byte release")
		}
	case FindingObserve:
	case FindingAuthorize:
		expected = AuthorizationPermit
	case FindingExempt:
		expected = AuthorizationExemption
	default:
		return fmt.Errorf("invalid finding disposition")
	}
	if d.Authorization.Kind != expected {
		return fmt.Errorf("finding and authorization kind disagree")
	}
	if expected == AuthorizationNone {
		if d.Authorization.Ref != "" || d.Authorization.Origin != "" {
			return fmt.Errorf("non-authorized finding has an authority reference or origin")
		}
	} else if !validIdentifier(d.Authorization.Ref) || !d.Authorization.Origin.valid() {
		return fmt.Errorf("named authority reference or origin is missing or invalid")
	}
	return nil
}

func (o Outcome) validate() error {
	if !slices.Contains([]Release{ReleaseNone, ReleasePartial, ReleaseComplete, ReleaseUnknown}, o.Release) ||
		!slices.Contains([]ByteForm{ByteFormNone, ByteFormOriginal, ByteFormTransformed, ByteFormUnknown}, o.ByteForm) {
		return fmt.Errorf("invalid observed byte outcome")
	}
	if (o.Release == ReleaseNone) != (o.ByteForm == ByteFormNone) {
		return fmt.Errorf("observed release and byte form disagree")
	}
	return nil
}

// ValidateAt binds typed producer facts to their immutable declared site.
// A standalone structurally valid event cannot establish registry membership.
func (d Decision) ValidateAt(registry *Registry) error {
	if err := d.Validate(); err != nil {
		return err
	}
	site, ok := registry.Lookup(d.SiteID)
	if !ok || site != d.site() {
		return fmt.Errorf("evidence decision does not match its registered site")
	}
	return nil
}

// ValidateOutcomeOf checks that an observation refers to the same selected
// decision as its intent. Envelope event IDs are deliberately outside this
// fixture-only model; a future receipt adapter must allocate a different event
// ID for each event while preserving these action and decision IDs. Observed
// release is never compared to planned release: a mismatch must remain
// representable as evidence of an enforcement failure.
func (d Decision) ValidateOutcomeOf(intent Decision) error {
	if err := intent.Validate(); err != nil {
		return fmt.Errorf("invalid evidence intent: %w", err)
	}
	if err := d.Validate(); err != nil {
		return fmt.Errorf("invalid evidence outcome: %w", err)
	}
	if intent.Phase != PhaseIntent || d.Phase != PhaseOutcome {
		return fmt.Errorf("evidence pairing requires intent and outcome phases")
	}
	selected := d
	selected.Phase = PhaseIntent
	selected.Outcome = nil
	selected.RewriteFallback = nil
	selected.DestinationRedaction = nil
	original := intent
	original.RewriteFallback = nil
	original.DestinationRedaction = nil
	if selected != original || !sameRewriteFallback(d.RewriteFallback, intent.RewriteFallback) ||
		!sameDestinationRedaction(d.DestinationRedaction, intent.DestinationRedaction) {
		return fmt.Errorf("evidence outcome changed the selected decision")
	}
	return nil
}

func sameDestinationRedaction(left, right *DestinationRedaction) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func sameRewriteFallback(left, right *RewriteFallback) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (d Decision) site() Site {
	return Site{
		ID: d.SiteID, Plane: d.Plane, Transport: d.Transport,
		Location: d.Location, View: d.View, Boundary: d.Boundary,
	}
}

func canonicalHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ToLower(host) != host {
		return false
	}
	// Share the destination parser so numeric aliases and mapped IPv4 do not
	// become distinct DNS identities in evidence. Comparison to the normalized
	// spelling also rejects zones and any alternate literal spelling.
	if ip := destination.ParseIPLiteral(host); ip != nil {
		return destination.NormalizeIP(ip).String() == host
	}
	// Invalid numeric hosts must not fall through as ordinary DNS identities:
	// this includes invalid component widths/counts and integer overflow. A
	// numeric earlier label is harmless when the last label is a DNS label.
	lastLabel := host[strings.LastIndexByte(host, '.')+1:]
	if numericHostLastLabelPattern.MatchString(lastLabel) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// The explicit key sets supplement DisallowUnknownFields, which otherwise
// accepts case-insensitive aliases of Go struct fields. Requiring every
// mandatory key also prevents absent fields from silently acquiring defaults.
func validateDecisionJSONShape(raw []byte) error {
	fields, err := decisionObject(raw, []string{
		"version", "action_id", "decision_id", "site_id", "plane", "transport",
		"location", "view", "boundary", "phase", "destination_kind",
		"pattern_class", "rule_id", "finding_disposition", "planned_byte_form",
		"authorization", "persistence_policy",
	}, []string{"destination_ref", "destination_redaction", "outcome", "rewrite_fallback"})
	if err != nil {
		return err
	}
	ref, hasRef := fields["destination_ref"]
	redaction, hasRedaction := fields["destination_redaction"]
	if hasRef == hasRedaction {
		return fmt.Errorf("evidence destination requires exactly one reference or redaction")
	}
	if hasRef {
		var value string
		if err := json.Unmarshal(ref, &value); err != nil || value == "" {
			return fmt.Errorf("invalid evidence destination reference")
		}
	} else if _, err := decisionObject(redaction, []string{"reason"}, nil); err != nil {
		return fmt.Errorf("invalid destination redaction object: %w", err)
	}
	authorization, err := decisionObject(fields["authorization"], []string{"kind"}, []string{"ref", "origin"})
	if err != nil {
		return fmt.Errorf("invalid authorization object: %w", err)
	}
	var kind AuthorizationKind
	if err := json.Unmarshal(authorization["kind"], &kind); err != nil {
		return fmt.Errorf("invalid authorization kind")
	}
	if kind == AuthorizationNone {
		if _, ok := authorization["ref"]; ok {
			return fmt.Errorf("non-authorized finding has an authority reference")
		}
		if _, ok := authorization["origin"]; ok {
			return fmt.Errorf("non-authorized finding has an authority origin")
		}
	}
	if fallback, ok := fields["rewrite_fallback"]; ok {
		if _, err := decisionObject(fallback, []string{"reason", "policy_ref", "policy_origin"}, nil); err != nil {
			return fmt.Errorf("invalid rewrite fallback object: %w", err)
		}
	}
	if outcome, ok := fields["outcome"]; ok {
		if _, err := decisionObject(outcome, []string{"release", "byte_form"}, nil); err != nil {
			return fmt.Errorf("invalid outcome object: %w", err)
		}
	}
	return nil
}

func decisionObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("evidence fields must be an object")
	}
	for key := range fields {
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			return nil, fmt.Errorf("unknown evidence field")
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("missing evidence field")
		}
	}
	return fields, nil
}
