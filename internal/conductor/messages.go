// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package conductor defines Conductor signed message bodies.
package conductor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion               = 1
	SignatureAlgorithmEd25519   = "ed25519"
	SignaturePrefixEd25519      = "ed25519:"
	RequiredStandardSigners     = 1
	RequiredCatastrophicSigners = 2
	MaxAuditPayloadBytes        = 1024 * 1024
	MaxConfigYAMLBytes          = 256 * 1024
	MaxReasonBytes              = 4 * 1024
	DefaultAuditMaxSkew         = 60 * time.Second
	MaxAllowedAuditSkew         = 300 * time.Second
	MaxIDBytes                  = 128
	MaxLabelKeyBytes            = 128
	MaxLabelValueBytes          = 256
	MaxDropReasons              = 32
	MaxDropReasonBytes          = 128
	MaxCapabilityThreshold      = 7
)

// acceptedSchemaVersions mirrors internal/recorder/entry.go's v1+v2 coexistence
// pattern. New writes use SchemaVersion; verifiers accept anything in the set so
// rolling fleet upgrades survive a schema bump. Extend by adding the new version
// key when the schema changes — never remove old keys without a release-note
// gate on rollout.
var acceptedSchemaVersions = map[int]bool{1: true}

var (
	ErrUnsupportedSchemaVersion = errors.New("unsupported conductor schema_version")
	ErrMissingField             = errors.New("missing required conductor field")
	ErrInvalidAudience          = errors.New("invalid conductor audience")
	ErrAudienceMismatch         = errors.New("conductor audience does not match follower")
	ErrInvalidHash              = errors.New("invalid conductor hash")
	ErrInvalidSignature         = errors.New("invalid conductor signature")
	ErrWrongKeyPurpose          = errors.New("conductor signature key_purpose mismatch")
	ErrThresholdRequired        = errors.New("conductor signature threshold not met")
	ErrForbiddenLicenseField    = errors.New("policy bundle contains forbidden license field")
	ErrInvalidValidityWindow    = errors.New("invalid conductor validity window")
	ErrInvalidSequenceRange     = errors.New("invalid conductor sequence range")
	ErrInvalidState             = errors.New("invalid conductor state")
	ErrInvalidRollback          = errors.New("invalid conductor rollback authorization")
	ErrNotYetValid              = errors.New("conductor message not yet valid (not_before in future)")
	ErrExpired                  = errors.New("conductor message expired")
	ErrSkewExceeded             = errors.New("conductor message exceeds allowed clock skew")
	ErrInvalidMinVersion        = errors.New("invalid min_pipelock_version")
	ErrHashMismatch             = errors.New("conductor hash mismatch")
	ErrPayloadTooLarge          = errors.New("conductor payload exceeds size cap")
	ErrInvalidAudienceWildcard  = errors.New("conductor audience cannot mix wildcard with explicit instance_ids")
	ErrInvalidAudienceSelectors = errors.New("conductor audience cannot mix instance_ids with labels")
	ErrInvalidReason            = errors.New("invalid conductor reason")
	ErrInvalidIdentifier        = errors.New("invalid conductor identifier")
	ErrSignatureVerification    = errors.New("conductor signature verification failed")
	ErrInvalidDroppedAccounting = errors.New("invalid conductor dropped accounting")
)

var forbiddenLicenseFields = map[string]struct{}{
	"license_key":               {},
	"license_file":              {},
	"license_crl_file":          {},
	"license_public_key":        {},
	"license_expires_at":        {},
	"license_id":                {},
	"license_crl_expires_at":    {},
	"license_crl_sha256":        {},
	"license_revoked":           {},
	"license_revocation_reason": {},
}

// SignatureKey carries the verification material plus the lifecycle metadata
// the spec mandates ("key_id, purpose, created_at, not_before, not_after,
// revoked_at"). The roster must populate NotBefore/NotAfter for every key; an
// unset NotAfter is treated as never-expires. RevokedAt set to a non-nil
// timestamp causes verification to reject regardless of the other windows.
type SignatureKey struct {
	PublicKey  ed25519.PublicKey
	KeyPurpose signing.KeyPurpose
	NotBefore  time.Time
	NotAfter   time.Time
	RevokedAt  *time.Time
}

// SignatureKeyResolver maps a signer key ID to its roster entry. Today the
// verifier calls the resolver serially per signature, so simple map-based
// resolvers without locks are safe. Implementations must remain safe under
// concurrent invocation: future parallel-verify paths cannot break a resolver
// that today assumes single-threaded calls.
type SignatureKeyResolver func(signerKeyID string) (SignatureKey, error)

type SignatureProof struct {
	SignerKeyID string             `json:"signer_key_id"`
	KeyPurpose  signing.KeyPurpose `json:"key_purpose"`
	Algorithm   string             `json:"algorithm"`
	Signature   string             `json:"signature"`
}

type Audience struct {
	InstanceIDs []string          `json:"instance_ids,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

type DroppedReason struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

type DroppedAccounting struct {
	Count   uint64          `json:"count"`
	Reasons []DroppedReason `json:"reasons,omitempty"`
}

type RuleBundleRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type PolicyBundlePayload struct {
	ConfigYAML  string          `json:"config_yaml"`
	RuleBundles []RuleBundleRef `json:"rule_bundles,omitempty"`
}

func (p PolicyBundlePayload) PayloadHash() (string, error) {
	return canonicalValueHash(p, "policy_bundle_payload")
}

func (p PolicyBundlePayload) PolicyHash() (string, error) {
	var cfg any
	decoder := yaml.NewDecoder(strings.NewReader(p.ConfigYAML))
	if err := decoder.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("parse policy bundle config_yaml for policy hash: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		if !isEmptyYAMLDocument(extra) {
			return "", fmt.Errorf("%w: config_yaml has multiple YAML documents", ErrInvalidHash)
		}
	} else if !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("parse policy bundle config_yaml trailing document: %w", err)
	}
	view := struct {
		ConfigYAML  any             `json:"config_yaml"`
		RuleBundles []RuleBundleRef `json:"rule_bundles,omitempty"`
	}{
		ConfigYAML:  cfg,
		RuleBundles: p.RuleBundles,
	}
	return canonicalValueHash(view, "policy_bundle_policy")
}

type PolicyBundle struct {
	SchemaVersion      int                 `json:"schema_version"`
	BundleID           string              `json:"bundle_id"`
	OrgID              string              `json:"org_id"`
	FleetID            string              `json:"fleet_id"`
	Environment        string              `json:"environment"`
	Audience           Audience            `json:"audience"`
	Version            uint64              `json:"version"`
	PreviousBundleHash string              `json:"previous_bundle_hash,omitempty"`
	CreatedAt          time.Time           `json:"created_at"`
	NotBefore          time.Time           `json:"not_before"`
	ExpiresAt          time.Time           `json:"expires_at"`
	MinPipelockVersion string              `json:"min_pipelock_version"`
	PolicyHash         string              `json:"policy_hash"`
	PayloadSHA256      string              `json:"payload_sha256"`
	Payload            PolicyBundlePayload `json:"payload"`
	Signatures         []SignatureProof    `json:"signatures,omitempty"`
}

type KillSwitchState string

const (
	KillSwitchInactive KillSwitchState = "inactive"
	KillSwitchActive   KillSwitchState = "active"
)

type RemoteKillMessage struct {
	SchemaVersion int              `json:"schema_version"`
	MessageID     string           `json:"message_id"`
	OrgID         string           `json:"org_id"`
	FleetID       string           `json:"fleet_id"`
	Audience      Audience         `json:"audience"`
	State         KillSwitchState  `json:"state"`
	Counter       uint64           `json:"counter"`
	Reason        string           `json:"reason"`
	CreatedAt     time.Time        `json:"created_at"`
	NotBefore     time.Time        `json:"not_before"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Signatures    []SignatureProof `json:"signatures,omitempty"`
}

type RollbackAuthorization struct {
	SchemaVersion   int              `json:"schema_version"`
	AuthorizationID string           `json:"authorization_id"`
	OrgID           string           `json:"org_id"`
	FleetID         string           `json:"fleet_id"`
	Audience        Audience         `json:"audience"`
	CurrentBundleID string           `json:"current_bundle_id"`
	CurrentVersion  uint64           `json:"current_version"`
	TargetBundleID  string           `json:"target_bundle_id"`
	TargetVersion   uint64           `json:"target_version"`
	Counter         uint64           `json:"counter"`
	Reason          string           `json:"reason"`
	CreatedAt       time.Time        `json:"created_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
	Signatures      []SignatureProof `json:"signatures,omitempty"`
}

type EvidenceChain struct {
	EntryVersion           int    `json:"entry_version"`
	SegmentID              string `json:"segment_id"`
	SeqStart               uint64 `json:"seq_start"`
	SeqEnd                 uint64 `json:"seq_end"`
	PreviousSegmentTail    string `json:"previous_segment_tail,omitempty"`
	SegmentHeadHash        string `json:"segment_head_hash"`
	SegmentTailHash        string `json:"segment_tail_hash"`
	CheckpointSeq          uint64 `json:"checkpoint_seq"`
	CheckpointHash         string `json:"checkpoint_hash"`
	CheckpointSignature    string `json:"checkpoint_signature"`
	CheckpointSignerKeyID  string `json:"checkpoint_signer_key_id"`
	FollowerRecorderKeyID  string `json:"follower_recorder_key_id"`
	FollowerRecorderPubHex string `json:"follower_recorder_public_key_hex"`
}

type AuditBatchEnvelope struct {
	SchemaVersion      int               `json:"schema_version"`
	BatchID            string            `json:"batch_id"`
	OrgID              string            `json:"org_id"`
	FleetID            string            `json:"fleet_id"`
	InstanceID         string            `json:"instance_id"`
	AuditSchemaVersion int               `json:"audit_schema_version"`
	EmittedAt          time.Time         `json:"emitted_at"`
	SeqStart           uint64            `json:"seq_start"`
	SeqEnd             uint64            `json:"seq_end"`
	EventCount         uint64            `json:"event_count"`
	PayloadSHA256      string            `json:"payload_sha256"`
	PayloadBytes       uint64            `json:"payload_bytes"`
	Dropped            DroppedAccounting `json:"dropped"`
	Chain              EvidenceChain     `json:"chain"`
	Signatures         []SignatureProof  `json:"signatures,omitempty"`
}

type SchemaRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type CapabilitiesResponse struct {
	SchemaVersion          int         `json:"schema_version"`
	ConductorID            string      `json:"conductor_id"`
	RequiredMTLS           bool        `json:"required_mtls"`
	ConductorBundle        SchemaRange `json:"conductor_bundle"`
	RemoteKill             SchemaRange `json:"remote_kill"`
	RollbackAuthorization  SchemaRange `json:"rollback_authorization"`
	AuditBatch             SchemaRange `json:"audit_batch"`
	ReceiptEntryVersions   []int       `json:"receipt_entry_versions"`
	MaxCreatedSkewSeconds  int         `json:"max_created_skew_seconds"`
	EmergencyStream        bool        `json:"emergency_stream"`
	RemoteKillThreshold    int         `json:"remote_kill_threshold"`
	RollbackThreshold      int         `json:"rollback_threshold"`
	TrustRotationThreshold int         `json:"trust_rotation_threshold"`
}

func (p SignatureProof) Validate(required signing.KeyPurpose) error {
	if strings.TrimSpace(p.SignerKeyID) == "" {
		return fmt.Errorf("%w: signature.signer_key_id", ErrMissingField)
	}
	if err := validateIdentifier("signature.signer_key_id", p.SignerKeyID); err != nil {
		return err
	}
	if p.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("%w: algorithm=%q", ErrInvalidSignature, p.Algorithm)
	}
	if err := p.KeyPurpose.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	if p.KeyPurpose != required {
		return fmt.Errorf("%w: required=%q got=%q", ErrWrongKeyPurpose, required, p.KeyPurpose)
	}
	if err := validateEd25519SignatureString(p.Signature); err != nil {
		return err
	}
	return nil
}

func (a Audience) Validate() error {
	if len(a.InstanceIDs) == 0 && len(a.Labels) == 0 {
		return fmt.Errorf("%w: empty audience", ErrInvalidAudience)
	}
	if len(a.InstanceIDs) > 0 && len(a.Labels) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalidAudience, ErrInvalidAudienceSelectors)
	}
	wildcard := false
	for _, id := range a.InstanceIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("%w: empty instance_id", ErrInvalidAudience)
		}
		if id != "*" {
			if err := validateIdentifier("audience.instance_ids", id); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidAudience, err)
			}
		}
		if id == "*" {
			wildcard = true
		}
	}
	if wildcard && len(a.InstanceIDs) > 1 {
		// Mixing "*" with explicit IDs is always wildcard but the explicit
		// entries imply scoped intent. Reject so operators don't ship a
		// fleet-wide bundle thinking it was scoped.
		return fmt.Errorf("%w: %w", ErrInvalidAudience, ErrInvalidAudienceWildcard)
	}
	for k, v := range a.Labels {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: empty label selector", ErrInvalidAudience)
		}
		if err := validateLabelSelector(k, v); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidAudience, err)
		}
	}
	return nil
}

func (d DroppedAccounting) Validate() error {
	if d.Count == 0 {
		if len(d.Reasons) != 0 {
			return fmt.Errorf("%w: reasons present with zero count", ErrInvalidDroppedAccounting)
		}
		return nil
	}
	if len(d.Reasons) == 0 {
		return fmt.Errorf("%w: count without reasons", ErrInvalidDroppedAccounting)
	}
	if len(d.Reasons) > MaxDropReasons {
		return fmt.Errorf("%w: %d reasons > cap %d", ErrInvalidDroppedAccounting, len(d.Reasons), MaxDropReasons)
	}
	var total uint64
	seen := make(map[string]struct{}, len(d.Reasons))
	for _, r := range d.Reasons {
		if err := r.Validate(); err != nil {
			return err
		}
		if _, dup := seen[r.Reason]; dup {
			return fmt.Errorf("%w: duplicate reason %q", ErrInvalidDroppedAccounting, r.Reason)
		}
		seen[r.Reason] = struct{}{}
		// Detect overflow before accumulating. An attacker crafting a batch
		// directly could otherwise pick Reason.Count values whose sum wraps
		// uint64 to land back on d.Count, satisfying the equality check with
		// an inconsistent payload.
		if r.Count > math.MaxUint64-total {
			return fmt.Errorf("%w: reason count sum overflows uint64", ErrInvalidDroppedAccounting)
		}
		total += r.Count
	}
	if total != d.Count {
		return fmt.Errorf("%w: count=%d reason_total=%d", ErrInvalidDroppedAccounting, d.Count, total)
	}
	return nil
}

func (r DroppedReason) Validate() error {
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("%w: dropped.reason", ErrMissingField)
	}
	if len(r.Reason) > MaxDropReasonBytes {
		return fmt.Errorf("%w: dropped.reason (%d bytes > cap %d)", ErrPayloadTooLarge, len(r.Reason), MaxDropReasonBytes)
	}
	if err := validateIdentifier("dropped.reason", r.Reason); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDroppedAccounting, err)
	}
	if r.Count == 0 {
		return fmt.Errorf("%w: dropped.reason.count", ErrMissingField)
	}
	return nil
}

func (a Audience) Matches(instanceID string, labels map[string]string) bool {
	if slices.Contains(a.InstanceIDs, "*") || slices.Contains(a.InstanceIDs, instanceID) {
		return true
	}
	if len(a.Labels) == 0 {
		return false
	}
	for k, want := range a.Labels {
		if labels[k] != want {
			return false
		}
	}
	return true
}

func (b PolicyBundle) SignablePreimage() ([]byte, error) {
	unsigned := b
	unsigned.Signatures = nil
	// Force UTC + RFC3339Nano-compatible representation so two producers in
	// different timezones canonicalize identically. Without this, the default
	// time.Time JSON marshal embeds the source zone offset and breaks signature
	// portability across regions / Conductor replicas.
	unsigned.CreatedAt = unsigned.CreatedAt.UTC()
	unsigned.NotBefore = unsigned.NotBefore.UTC()
	unsigned.ExpiresAt = unsigned.ExpiresAt.UTC()
	return canonicalPreimage(unsigned, "policy_bundle")
}

func (b PolicyBundle) CanonicalHash() (string, error) {
	return canonicalHash(b.SignablePreimage)
}

func (b PolicyBundle) Validate() error {
	if err := validateSchemaVersion(b.SchemaVersion); err != nil {
		return err
	}
	if err := validateIdentifier("bundle_id", b.BundleID); err != nil {
		return err
	}
	if err := validateOrgFleet(b.OrgID, b.FleetID); err != nil {
		return err
	}
	if err := validateIdentifier("environment", b.Environment); err != nil {
		return err
	}
	if err := b.Audience.Validate(); err != nil {
		return err
	}
	if b.Version == 0 {
		return fmt.Errorf("%w: version", ErrMissingField)
	}
	if err := validateWindow(b.NotBefore, b.ExpiresAt); err != nil {
		return err
	}
	if b.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at", ErrMissingField)
	}
	if err := validateHash("policy_hash", b.PolicyHash); err != nil {
		return err
	}
	if err := validateHash("payload_sha256", b.PayloadSHA256); err != nil {
		return err
	}
	if b.PreviousBundleHash != "" {
		if err := validateHash("previous_bundle_hash", b.PreviousBundleHash); err != nil {
			return err
		}
	}
	if strings.TrimSpace(b.Payload.ConfigYAML) == "" {
		return fmt.Errorf("%w: payload.config_yaml", ErrMissingField)
	}
	if len(b.Payload.ConfigYAML) > MaxConfigYAMLBytes {
		return fmt.Errorf("%w: payload.config_yaml (%d bytes > cap %d)", ErrPayloadTooLarge, len(b.Payload.ConfigYAML), MaxConfigYAMLBytes)
	}
	if err := validateMinPipelockVersion(b.MinPipelockVersion); err != nil {
		return err
	}
	if err := rejectLicenseFields(b.Payload.ConfigYAML); err != nil {
		return err
	}
	for _, rb := range b.Payload.RuleBundles {
		if err := rb.Validate(); err != nil {
			return err
		}
	}
	if err := b.validateHashes(); err != nil {
		return err
	}
	return validateSignatureThreshold(b.Signatures, signing.PurposePolicyBundleSigning, RequiredStandardSigners)
}

func (b PolicyBundle) validateHashes() error {
	payloadHash, err := b.Payload.PayloadHash()
	if err != nil {
		return err
	}
	if !strings.EqualFold(b.PayloadSHA256, payloadHash) {
		return fmt.Errorf("%w: payload_sha256", ErrHashMismatch)
	}
	policyHash, err := b.Payload.PolicyHash()
	if err != nil {
		return err
	}
	if !strings.EqualFold(b.PolicyHash, policyHash) {
		return fmt.Errorf("%w: policy_hash", ErrHashMismatch)
	}
	return nil
}

// ValidateAtTime extends Validate with a freshness check: now must fall inside
// [NotBefore, ExpiresAt]. Callers that apply the bundle must use this variant —
// Validate alone passes a future-dated or already-expired bundle.
func (b PolicyBundle) ValidateAtTime(now time.Time) error {
	if err := b.Validate(); err != nil {
		return err
	}
	return withinValidity(now, b.NotBefore, b.ExpiresAt)
}

// VerifySignatures is shorthand for VerifySignaturesAt(time.Now(), resolve).
// Callers that already have a logical clock (e.g. apply pipelines that took
// "now" once at the top of the operation) should prefer VerifySignaturesAt so
// roster lifecycle checks use the same instant as freshness checks.
func (b PolicyBundle) VerifySignatures(resolve SignatureKeyResolver) error {
	return b.VerifySignaturesAt(time.Now(), resolve)
}

func (b PolicyBundle) VerifySignaturesAt(now time.Time, resolve SignatureKeyResolver) error {
	preimage, err := b.SignablePreimage()
	if err != nil {
		return err
	}
	return verifySignatureThreshold(now, preimage, b.Signatures, signing.PurposePolicyBundleSigning, RequiredStandardSigners, resolve)
}

func (b PolicyBundle) ValidateForFollower(orgID, fleetID, instanceID string, labels map[string]string) error {
	if b.OrgID != orgID || b.FleetID != fleetID {
		return fmt.Errorf("%w: org_id/fleet_id", ErrAudienceMismatch)
	}
	if !b.Audience.Matches(instanceID, labels) {
		return fmt.Errorf("%w: instance_id=%q", ErrAudienceMismatch, instanceID)
	}
	return nil
}

func (r RuleBundleRef) Validate() error {
	if err := validateIdentifier("rule_bundles.name", r.Name); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_bundles.version", r.Version); err != nil {
		return err
	}
	return validateHash("rule_bundles.sha256", r.SHA256)
}

func (m RemoteKillMessage) SignablePreimage() ([]byte, error) {
	unsigned := m
	unsigned.Signatures = nil
	unsigned.CreatedAt = unsigned.CreatedAt.UTC()
	unsigned.NotBefore = unsigned.NotBefore.UTC()
	unsigned.ExpiresAt = unsigned.ExpiresAt.UTC()
	return canonicalPreimage(unsigned, "remote_kill")
}

func (m RemoteKillMessage) CanonicalHash() (string, error) {
	return canonicalHash(m.SignablePreimage)
}

func (m RemoteKillMessage) Validate() error {
	if err := validateSchemaVersion(m.SchemaVersion); err != nil {
		return err
	}
	if err := validateIdentifier("message_id", m.MessageID); err != nil {
		return err
	}
	if err := validateOrgFleet(m.OrgID, m.FleetID); err != nil {
		return err
	}
	if err := m.Audience.Validate(); err != nil {
		return err
	}
	if m.State != KillSwitchActive && m.State != KillSwitchInactive {
		return fmt.Errorf("%w: state=%q", ErrInvalidState, m.State)
	}
	if m.Counter == 0 {
		return fmt.Errorf("%w: counter", ErrMissingField)
	}
	if err := validateWindow(m.NotBefore, m.ExpiresAt); err != nil {
		return err
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at", ErrMissingField)
	}
	if err := validateReason("reason", m.Reason); err != nil {
		return err
	}
	return validateSignatureThreshold(m.Signatures, signing.PurposeRemoteKillSigning, RequiredCatastrophicSigners)
}

// ValidateAtTime extends Validate with a freshness check. Remote kill messages
// have tight TTLs by design; an expired remote-kill must be rejected even if
// signature, threshold, and audience all pass.
func (m RemoteKillMessage) ValidateAtTime(now time.Time) error {
	if err := m.Validate(); err != nil {
		return err
	}
	return withinValidity(now, m.NotBefore, m.ExpiresAt)
}

func (m RemoteKillMessage) VerifySignatures(resolve SignatureKeyResolver) error {
	return m.VerifySignaturesAt(time.Now(), resolve)
}

func (m RemoteKillMessage) VerifySignaturesAt(now time.Time, resolve SignatureKeyResolver) error {
	preimage, err := m.SignablePreimage()
	if err != nil {
		return err
	}
	return verifySignatureThreshold(now, preimage, m.Signatures, signing.PurposeRemoteKillSigning, RequiredCatastrophicSigners, resolve)
}

func (m RemoteKillMessage) ValidateForFollower(orgID, fleetID, instanceID string, labels map[string]string) error {
	if m.OrgID != orgID || m.FleetID != fleetID {
		return fmt.Errorf("%w: org_id/fleet_id", ErrAudienceMismatch)
	}
	if !m.Audience.Matches(instanceID, labels) {
		return fmt.Errorf("%w: instance_id=%q", ErrAudienceMismatch, instanceID)
	}
	return nil
}

func (r RollbackAuthorization) SignablePreimage() ([]byte, error) {
	unsigned := r
	unsigned.Signatures = nil
	unsigned.CreatedAt = unsigned.CreatedAt.UTC()
	unsigned.ExpiresAt = unsigned.ExpiresAt.UTC()
	return canonicalPreimage(unsigned, "rollback_authorization")
}

func (r RollbackAuthorization) CanonicalHash() (string, error) {
	return canonicalHash(r.SignablePreimage)
}

func (r RollbackAuthorization) Validate() error {
	if err := validateSchemaVersion(r.SchemaVersion); err != nil {
		return err
	}
	if err := validateIdentifier("authorization_id", r.AuthorizationID); err != nil {
		return err
	}
	if err := validateOrgFleet(r.OrgID, r.FleetID); err != nil {
		return err
	}
	if err := r.Audience.Validate(); err != nil {
		return err
	}
	if err := validateIdentifier("current_bundle_id", r.CurrentBundleID); err != nil {
		return err
	}
	if err := validateIdentifier("target_bundle_id", r.TargetBundleID); err != nil {
		return err
	}
	if r.CurrentVersion == 0 || r.TargetVersion == 0 || r.Counter == 0 {
		return fmt.Errorf("%w: rollback counters", ErrMissingField)
	}
	if r.TargetVersion >= r.CurrentVersion {
		return fmt.Errorf("%w: target_version must be lower than current_version", ErrInvalidRollback)
	}
	if r.CreatedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) {
		return fmt.Errorf("%w: rollback validity", ErrInvalidValidityWindow)
	}
	if err := validateReason("reason", r.Reason); err != nil {
		return err
	}
	return validateSignatureThreshold(r.Signatures, signing.PurposePolicyBundleRollback, RequiredCatastrophicSigners)
}

// ValidateAtTime extends Validate with a freshness check. Rollback
// authorizations are single-shot; an expired authorization must not be
// applicable even if the operator hasn't redacted it.
func (r RollbackAuthorization) ValidateAtTime(now time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	return withinValidity(now, r.CreatedAt, r.ExpiresAt)
}

func (r RollbackAuthorization) VerifySignatures(resolve SignatureKeyResolver) error {
	return r.VerifySignaturesAt(time.Now(), resolve)
}

func (r RollbackAuthorization) VerifySignaturesAt(now time.Time, resolve SignatureKeyResolver) error {
	preimage, err := r.SignablePreimage()
	if err != nil {
		return err
	}
	return verifySignatureThreshold(now, preimage, r.Signatures, signing.PurposePolicyBundleRollback, RequiredCatastrophicSigners, resolve)
}

func (a AuditBatchEnvelope) SignablePreimage() ([]byte, error) {
	unsigned := a
	unsigned.Signatures = nil
	unsigned.EmittedAt = unsigned.EmittedAt.UTC()
	return canonicalPreimage(unsigned, "audit_batch")
}

func (a AuditBatchEnvelope) CanonicalHash() (string, error) {
	return canonicalHash(a.SignablePreimage)
}

func (a AuditBatchEnvelope) Validate() error {
	if err := validateSchemaVersion(a.SchemaVersion); err != nil {
		return err
	}
	if err := validateIdentifier("batch_id", a.BatchID); err != nil {
		return err
	}
	if err := validateOrgFleet(a.OrgID, a.FleetID); err != nil {
		return err
	}
	if err := validateIdentifier("instance_id", a.InstanceID); err != nil {
		return err
	}
	if a.AuditSchemaVersion <= 0 {
		return fmt.Errorf("%w: audit_schema_version", ErrMissingField)
	}
	if a.EmittedAt.IsZero() {
		return fmt.Errorf("%w: emitted_at", ErrMissingField)
	}
	if err := validateSeqRange(a.SeqStart, a.SeqEnd); err != nil {
		return err
	}
	if a.EventCount == 0 {
		return fmt.Errorf("%w: event_count", ErrMissingField)
	}
	if a.PayloadBytes == 0 {
		return fmt.Errorf("%w: payload_bytes", ErrMissingField)
	}
	if a.PayloadBytes > MaxAuditPayloadBytes {
		return fmt.Errorf("%w: payload_bytes=%d cap=%d", ErrPayloadTooLarge, a.PayloadBytes, MaxAuditPayloadBytes)
	}
	if err := validateHash("payload_sha256", a.PayloadSHA256); err != nil {
		return err
	}
	if err := a.Dropped.Validate(); err != nil {
		return err
	}
	if err := a.Chain.Validate(a.SeqStart, a.SeqEnd); err != nil {
		return err
	}
	return validateSignatureThreshold(a.Signatures, signing.PurposeAuditBatchSigning, RequiredStandardSigners)
}

// ValidateForConductor extends Validate with skew enforcement against Conductor's clock.
// maxSkew bounds |now - EmittedAt|; replay protection requires this be tight
// (default DefaultAuditMaxSkew, ceiling MaxAllowedAuditSkew). Callers that
// configure a higher skew must do so consciously and log a warning at config
// load time. Validate alone does NOT enforce skew — a captured signed batch
// could otherwise be replayed at any future time.
func (a AuditBatchEnvelope) ValidateForConductor(now time.Time, maxSkew time.Duration) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if maxSkew <= 0 {
		maxSkew = DefaultAuditMaxSkew
	}
	if maxSkew > MaxAllowedAuditSkew {
		return fmt.Errorf("%w: max_skew %s exceeds ceiling %s", ErrSkewExceeded, maxSkew, MaxAllowedAuditSkew)
	}
	delta := now.Sub(a.EmittedAt)
	if delta < 0 {
		delta = -delta
	}
	if delta > maxSkew {
		return fmt.Errorf("%w: |now-emitted_at|=%s max_skew=%s", ErrSkewExceeded, delta, maxSkew)
	}
	return nil
}

func (a AuditBatchEnvelope) ValidatePayload(payload []byte) error {
	if uint64(len(payload)) != a.PayloadBytes {
		return fmt.Errorf("%w: payload_bytes envelope=%d actual=%d", ErrHashMismatch, a.PayloadBytes, len(payload))
	}
	sum := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), a.PayloadSHA256) {
		return fmt.Errorf("%w: payload_sha256", ErrHashMismatch)
	}
	return nil
}

func (a AuditBatchEnvelope) ValidateForConductorWithPayload(now time.Time, maxSkew time.Duration, payload []byte) error {
	if err := a.ValidateForConductor(now, maxSkew); err != nil {
		return err
	}
	return a.ValidatePayload(payload)
}

func (a AuditBatchEnvelope) VerifySignatures(resolve SignatureKeyResolver) error {
	return a.VerifySignaturesAt(time.Now(), resolve)
}

func (a AuditBatchEnvelope) VerifySignaturesAt(now time.Time, resolve SignatureKeyResolver) error {
	preimage, err := a.SignablePreimage()
	if err != nil {
		return err
	}
	return verifySignatureThreshold(now, preimage, a.Signatures, signing.PurposeAuditBatchSigning, RequiredStandardSigners, resolve)
}

func (a AuditBatchEnvelope) ForksWith(other AuditBatchEnvelope) bool {
	if a.OrgID != other.OrgID || a.FleetID != other.FleetID || a.InstanceID != other.InstanceID {
		return false
	}
	if a.SeqEnd < other.SeqStart || other.SeqEnd < a.SeqStart {
		return false
	}
	return a.PayloadSHA256 != other.PayloadSHA256 || a.Chain.SegmentTailHash != other.Chain.SegmentTailHash
}

func (c EvidenceChain) Validate(seqStart, seqEnd uint64) error {
	if c.EntryVersion != 2 {
		return fmt.Errorf("%w: entry_version=%d", ErrInvalidSequenceRange, c.EntryVersion)
	}
	if err := validateIdentifier("chain.segment_id", c.SegmentID); err != nil {
		return err
	}
	if c.SeqStart != seqStart || c.SeqEnd != seqEnd {
		return fmt.Errorf("%w: chain seq range mismatch", ErrInvalidSequenceRange)
	}
	if err := validateSeqRange(c.SeqStart, c.SeqEnd); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"chain.segment_head_hash": c.SegmentHeadHash,
		"chain.segment_tail_hash": c.SegmentTailHash,
		"chain.checkpoint_hash":   c.CheckpointHash,
	} {
		if err := validateHash(name, value); err != nil {
			return err
		}
	}
	if c.PreviousSegmentTail != "" {
		if err := validateHash("chain.previous_segment_tail", c.PreviousSegmentTail); err != nil {
			return err
		}
	}
	if c.CheckpointSeq < c.SeqStart || c.CheckpointSeq > c.SeqEnd {
		return fmt.Errorf("%w: checkpoint_seq", ErrInvalidSequenceRange)
	}
	if err := validateEd25519SignatureString(c.CheckpointSignature); err != nil {
		return err
	}
	if err := validateIdentifier("chain.checkpoint_signer_key_id", c.CheckpointSignerKeyID); err != nil {
		return err
	}
	if err := validateIdentifier("chain.follower_recorder_key_id", c.FollowerRecorderKeyID); err != nil {
		return err
	}
	if err := validatePublicKeyHex("chain.follower_recorder_public_key_hex", c.FollowerRecorderPubHex); err != nil {
		return err
	}
	return nil
}

func (c CapabilitiesResponse) Validate() error {
	return c.ValidateWithLocalThresholdCap(MaxCapabilityThreshold)
}

func (c CapabilitiesResponse) ValidateWithLocalThresholdCap(maxThreshold int) error {
	if err := validateSchemaVersion(c.SchemaVersion); err != nil {
		return err
	}
	if err := validateIdentifier("conductor_id", c.ConductorID); err != nil {
		return err
	}
	if !c.RequiredMTLS {
		return fmt.Errorf("%w: required_mtls must be true", ErrInvalidState)
	}
	for name, r := range map[string]SchemaRange{
		"conductor_bundle":       c.ConductorBundle,
		"remote_kill":            c.RemoteKill,
		"rollback_authorization": c.RollbackAuthorization,
		"audit_batch":            c.AuditBatch,
	} {
		if err := r.Validate(name); err != nil {
			return err
		}
	}
	// Couple to recorder.EntryVersion — the version the local recorder
	// actively WRITES — so a recorder bump (v2→v3) automatically tightens
	// the handshake instead of leaving this stranded on a hardcoded "2".
	// Conductor must advertise that version or the follower can never produce
	// ingestable batches.
	if !slices.Contains(c.ReceiptEntryVersions, recorder.EntryVersion) {
		return fmt.Errorf("%w: receipt_entry_versions must include recorder write version %d", ErrInvalidState, recorder.EntryVersion)
	}
	if c.MaxCreatedSkewSeconds <= 0 || time.Duration(c.MaxCreatedSkewSeconds)*time.Second > MaxAllowedAuditSkew {
		return fmt.Errorf("%w: max_created_skew_seconds=%d", ErrSkewExceeded, c.MaxCreatedSkewSeconds)
	}
	for name, value := range map[string]int{
		"remote_kill_threshold":    c.RemoteKillThreshold,
		"rollback_threshold":       c.RollbackThreshold,
		"trust_rotation_threshold": c.TrustRotationThreshold,
	} {
		if value < RequiredCatastrophicSigners {
			return fmt.Errorf("%w: %s=%d", ErrThresholdRequired, name, value)
		}
		if maxThreshold > 0 && value > maxThreshold {
			return fmt.Errorf("%w: %s=%d exceeds local cap %d", ErrThresholdRequired, name, value, maxThreshold)
		}
	}
	return nil
}

func (r SchemaRange) Validate(name string) error {
	if r.Min <= 0 || r.Max < r.Min {
		return fmt.Errorf("%w: %s schema range", ErrInvalidState, name)
	}
	if SchemaVersion < r.Min || SchemaVersion > r.Max {
		return fmt.Errorf("%w: %s must include schema_version %d", ErrInvalidState, name, SchemaVersion)
	}
	return nil
}

func validateSignatureThreshold(signatures []SignatureProof, required signing.KeyPurpose, minSigners int) error {
	if len(signatures) == 0 {
		return fmt.Errorf("%w: signatures", ErrThresholdRequired)
	}
	seen := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		if err := sig.Validate(required); err != nil {
			return err
		}
		seen[sig.SignerKeyID] = struct{}{}
	}
	if len(seen) < minSigners {
		return fmt.Errorf("%w: got %d distinct signer(s), want %d", ErrThresholdRequired, len(seen), minSigners)
	}
	return nil
}

func verifySignatureThreshold(
	now time.Time,
	preimage []byte,
	signatures []SignatureProof,
	required signing.KeyPurpose,
	minSigners int,
	resolve SignatureKeyResolver,
) error {
	if resolve == nil {
		return fmt.Errorf("%w: nil key resolver", ErrSignatureVerification)
	}
	if len(signatures) == 0 {
		return fmt.Errorf("%w: signatures", ErrThresholdRequired)
	}
	now = now.UTC()
	seenIDs := make(map[string]struct{}, len(signatures))
	seenKeys := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		if err := sig.Validate(required); err != nil {
			return err
		}
		key, err := resolve(sig.SignerKeyID)
		if err != nil {
			return fmt.Errorf("%w: key_id=%q: %w", ErrSignatureVerification, sig.SignerKeyID, err)
		}
		if key.KeyPurpose != required {
			return fmt.Errorf("%w: key_id=%q roster purpose=%q required=%q", ErrWrongKeyPurpose, sig.SignerKeyID, key.KeyPurpose, required)
		}
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: key_id=%q public key length=%d", ErrSignatureVerification, sig.SignerKeyID, len(key.PublicKey))
		}
		if err := key.checkLifecycle(now); err != nil {
			return fmt.Errorf("%w: key_id=%q: %w", ErrSignatureVerification, sig.SignerKeyID, err)
		}
		sigBytes, err := parseEd25519SignatureString(sig.Signature)
		if err != nil {
			return err
		}
		if !contract.VerifyEd25519PureEdDSA(key.PublicKey, preimage, sigBytes) {
			return fmt.Errorf("%w: key_id=%q", ErrSignatureVerification, sig.SignerKeyID)
		}
		seenIDs[sig.SignerKeyID] = struct{}{}
		// Track distinct PUBLIC KEYS, not just distinct IDs. A roster that
		// (maliciously or by misconfiguration) maps two IDs to the same
		// public key would otherwise satisfy the threshold with one
		// underlying signer.
		seenKeys[hex.EncodeToString(key.PublicKey)] = struct{}{}
	}
	if len(seenIDs) < minSigners {
		return fmt.Errorf("%w: got %d distinct signer id(s), want %d", ErrThresholdRequired, len(seenIDs), minSigners)
	}
	if len(seenKeys) < minSigners {
		return fmt.Errorf("%w: got %d distinct verified public key(s) across %d signer id(s), want %d", ErrThresholdRequired, len(seenKeys), len(seenIDs), minSigners)
	}
	return nil
}

// checkLifecycle rejects a roster key whose validity window has not begun, has
// ended, or that has been revoked. NotBefore zero is treated as "always valid
// from epoch", NotAfter zero as "never expires". RevokedAt non-nil rejects
// unconditionally — revocation overrides any window check.
func (k SignatureKey) checkLifecycle(now time.Time) error {
	if k.RevokedAt != nil {
		return fmt.Errorf("%w: revoked_at=%s verification_time=%s", ErrSignatureVerification, k.RevokedAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !k.NotBefore.IsZero() && now.Before(k.NotBefore.UTC()) {
		return fmt.Errorf("%w: not_before=%s verification_time=%s", ErrNotYetValid, k.NotBefore.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !k.NotAfter.IsZero() && now.After(k.NotAfter.UTC()) {
		return fmt.Errorf("%w: not_after=%s verification_time=%s", ErrExpired, k.NotAfter.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}

func canonicalPreimage(v any, name string) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", name, err)
	}
	tree, err := contract.ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s for canonicalization: %w", name, err)
	}
	return contract.Canonicalize(tree)
}

func canonicalHash(preimage func() ([]byte, error)) (string, error) {
	data, err := preimage()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalValueHash(v any, name string) (string, error) {
	data, err := canonicalPreimage(v, name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateSchemaVersion(v int) error {
	if !acceptedSchemaVersions[v] {
		return fmt.Errorf("%w: got %d", ErrUnsupportedSchemaVersion, v)
	}
	return nil
}

// withinValidity reports whether now ∈ [notBefore, expiresAt]. notBefore and
// expiresAt are presumed already shape-checked by validateWindow.
func withinValidity(now, notBefore, expiresAt time.Time) error {
	now = now.UTC()
	if now.Before(notBefore.UTC()) {
		return fmt.Errorf("%w: now=%s not_before=%s", ErrNotYetValid, now.Format(time.RFC3339), notBefore.UTC().Format(time.RFC3339))
	}
	if now.After(expiresAt.UTC()) {
		return fmt.Errorf("%w: now=%s expires_at=%s", ErrExpired, now.Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// validateMinPipelockVersion accepts a non-empty major.minor.patch semver-like
// shape. Full SemVer 2.0.0 (pre-release / build metadata) is intentionally not
// supported in MVP — bundles target release versions only. The follower-side
// sanity window (max_min_version_major_skew / minor_skew per spec) is enforced
// at apply time with the follower's runtime version on hand, not here.
func validateMinPipelockVersion(v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%w: min_pipelock_version", ErrMissingField)
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: %q (want major.minor.patch)", ErrInvalidMinVersion, v)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("%w: %q (empty component)", ErrInvalidMinVersion, v)
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("%w: %q (leading zero component %q)", ErrInvalidMinVersion, v, p)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return fmt.Errorf("%w: %q (non-numeric component %q)", ErrInvalidMinVersion, v, p)
			}
		}
	}
	return nil
}

// validateReason caps and constrains free-form reason strings used in
// remote-kill / rollback messages. Empty is allowed, but control characters
// are rejected at the signed-message boundary so downstream logs, terminals,
// web UIs, and pager paths do not all need to rediscover the same sanitization
// rule.
func validateReason(field, reason string) error {
	if len(reason) > MaxReasonBytes {
		return fmt.Errorf("%w: %s (%d bytes > cap %d)", ErrPayloadTooLarge, field, len(reason), MaxReasonBytes)
	}
	if !utf8.ValidString(reason) {
		return fmt.Errorf("%w: %s contains invalid utf-8", ErrInvalidReason, field)
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains control character U+%04X", ErrInvalidReason, field, r)
		}
	}
	return nil
}

func validateOrgFleet(orgID, fleetID string) error {
	if err := validateIdentifier("org_id", orgID); err != nil {
		return err
	}
	return validateIdentifier("fleet_id", fleetID)
}

func requireNonEmpty(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s", ErrMissingField, field)
	}
	return nil
}

// ValidateIdentifier is the canonical conductor identifier check. Use it from
// any package that receives operator- or transport-supplied identifiers
// (org_id, fleet_id, instance_id, environment, bundle_id, ...). Diverging
// identifier semantics between conductor base and conductor/controlplane risks
// stream-key collisions when SPIFFE SANs unescape to bytes that the base layer
// would reject (null bytes, slashes, control characters).
func ValidateIdentifier(field, value string) error {
	return validateIdentifier(field, value)
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s", ErrMissingField, field)
	}
	if len(value) > MaxIDBytes {
		return fmt.Errorf("%w: %s (%d bytes > cap %d)", ErrInvalidIdentifier, field, len(value), MaxIDBytes)
	}
	if !isIdentifier(value) {
		return fmt.Errorf("%w: %s=%q", ErrInvalidIdentifier, field, value)
	}
	return nil
}

func validateLabelSelector(key, value string) error {
	if len(key) > MaxLabelKeyBytes {
		return fmt.Errorf("%w: label key (%d bytes > cap %d)", ErrInvalidIdentifier, len(key), MaxLabelKeyBytes)
	}
	if len(value) > MaxLabelValueBytes {
		return fmt.Errorf("%w: label value (%d bytes > cap %d)", ErrInvalidIdentifier, len(value), MaxLabelValueBytes)
	}
	if !isIdentifier(key) || !isIdentifier(value) {
		return fmt.Errorf("%w: label %q=%q", ErrInvalidIdentifier, key, value)
	}
	return nil
}

func isIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '_', '-', '.':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validateWindow(notBefore, expiresAt time.Time) error {
	if notBefore.IsZero() || expiresAt.IsZero() || !expiresAt.After(notBefore) {
		return ErrInvalidValidityWindow
	}
	return nil
}

func validateSeqRange(start, end uint64) error {
	if end < start {
		return fmt.Errorf("%w: start=%d end=%d", ErrInvalidSequenceRange, start, end)
	}
	return nil
}

func validateHash(field, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%w: %s", ErrInvalidHash, field)
	}
	return nil
}

func validatePublicKeyHex(field, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%w: %s", ErrInvalidHash, field)
	}
	return nil
}

func validateEd25519SignatureString(value string) error {
	_, err := parseEd25519SignatureString(value)
	return err
}

func parseEd25519SignatureString(value string) ([]byte, error) {
	if !strings.HasPrefix(value, SignaturePrefixEd25519) {
		return nil, fmt.Errorf("%w: signature missing %q prefix", ErrInvalidSignature, SignaturePrefixEd25519)
	}
	hexPart := value[len(SignaturePrefixEd25519):]
	decoded, err := hex.DecodeString(hexPart)
	if err != nil || len(decoded) != 64 {
		return nil, fmt.Errorf("%w: malformed ed25519 signature", ErrInvalidSignature)
	}
	return decoded, nil
}

func rejectLicenseFields(configYAML string) error {
	dec := yaml.NewDecoder(bytes.NewReader([]byte(configYAML)))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("%w: parse config payload: %w", ErrForbiddenLicenseField, err)
	}
	if err := rejectExtraYAMLDocuments(dec); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	return walkRejectLicenseFields(doc.Content[0])
}

// walkRejectLicenseFields recurses through MappingNode / SequenceNode children
// and rejects any key that matches forbiddenLicenseFields at any depth. The
// shallow root-only check it replaces missed nested license fields under
// agents.<name> and any other future submap. Path is reported so an operator
// can see exactly which subpath tripped the rejection.
func walkRejectLicenseFields(n *yaml.Node) error {
	return walkRejectLicenseFieldsAt(n, "")
}

func walkRejectLicenseFieldsAt(n *yaml.Node, path string) error {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			if err := walkRejectLicenseFieldsAt(c, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]
			childPath := path + "." + key.Value
			if path == "" {
				childPath = key.Value
			}
			if _, forbidden := forbiddenLicenseFields[key.Value]; forbidden {
				return fmt.Errorf("%w: %s", ErrForbiddenLicenseField, childPath)
			}
			if err := walkRejectLicenseFieldsAt(val, childPath); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			if err := walkRejectLicenseFieldsAt(c, childPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectExtraYAMLDocuments(dec *yaml.Decoder) error {
	var extra yaml.Node
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: parse config payload: %w", ErrForbiddenLicenseField, err)
	}
	if !isEmptyYAMLDocument(extra) {
		return fmt.Errorf("%w: multiple YAML documents", ErrForbiddenLicenseField)
	}
	return nil
}

func isEmptyYAMLDocument(n yaml.Node) bool {
	if len(n.Content) == 0 {
		return true
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 {
		return false
	}
	child := n.Content[0]
	return child.Kind == yaml.ScalarNode && child.Tag == "!!null" && child.Value == ""
}
