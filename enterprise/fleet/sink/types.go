//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"context"
	"errors"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	// AuditBatchesPath is the stable follower-to-sink ingest endpoint.
	AuditBatchesPath = "/api/v1/conductor/audit/batches"

	// DefaultMaxRequestBytes admits the maximum signed audit payload plus the
	// envelope/signature wrapper while keeping hostile requests bounded.
	DefaultMaxRequestBytes = int64(conductor.MaxAuditPayloadBytes + 128*1024)
)

var (
	ErrMissingStore       = errors.New("fleet sink store is required")
	ErrMissingResolver    = errors.New("fleet sink signature resolver is required")
	ErrMissingDLPScanner  = errors.New("fleet sink DLP scanner is required")
	ErrBatchConflict      = errors.New("fleet sink batch id conflict")
	ErrForkDetected       = errors.New("fleet sink audit sequence fork detected")
	ErrDLPRejected        = errors.New("fleet sink DLP rejected audit payload")
	ErrUnsupportedMethod  = errors.New("fleet sink unsupported method")
	ErrUnsupportedPath    = errors.New("fleet sink unsupported path")
	ErrRequestTooLarge    = errors.New("fleet sink request body exceeds limit")
	ErrInvalidRequestBody = errors.New("fleet sink invalid request body")
	ErrUnauthorized       = errors.New("fleet sink unauthorized")
	ErrKeyBindingViolated = errors.New("fleet sink signing key not authorized for batch namespace")
)

// DLPScanner is the scanner surface the sink needs before storing evidence.
type DLPScanner interface {
	ScanTextForDLP(ctx context.Context, text string) scanner.TextDLPResult
}

// KeyBinding constrains a trusted audit signing key to a specific
// (OrgID, FleetID, InstanceID) namespace. Empty fields mean "any" —
// e.g. a key bound only to OrgID="acme" can sign for any fleet or
// instance within that org. A zero KeyBinding means the key is
// unrestricted. Bindings are enforced AFTER signature verification:
// a valid signature whose envelope namespace falls outside the
// configured binding is rejected as unauthorized.
type KeyBinding struct {
	OrgID      string
	FleetID    string
	InstanceID string
}

// Matches reports whether env's namespace satisfies the binding.
// A zero binding matches everything; otherwise each non-empty field
// must equal the corresponding envelope field exactly.
func (b KeyBinding) Matches(env conductor.AuditBatchEnvelope) bool {
	if b.OrgID != "" && b.OrgID != env.OrgID {
		return false
	}
	if b.FleetID != "" && b.FleetID != env.FleetID {
		return false
	}
	if b.InstanceID != "" && b.InstanceID != env.InstanceID {
		return false
	}
	return true
}

// IsZero reports whether the binding is unrestricted.
func (b KeyBinding) IsZero() bool {
	return b == KeyBinding{}
}

type Options struct {
	Store           *Store
	Resolver        conductor.SignatureKeyResolver
	DLPScanner      DLPScanner
	Now             func() time.Time
	MaxSkew         time.Duration
	MaxRequestBytes int64
	// KeyBindings, when populated, restricts each trusted signer key
	// id to a specific (org, fleet, instance) namespace. Map keys are
	// SignerKeyID. Missing entries default to unrestricted — callers
	// that want every key bound must populate the map for every id.
	KeyBindings map[string]KeyBinding
	// ReaderToken, when non-empty, requires a matching
	// "Authorization: Bearer <token>" header on GET requests to the
	// audit batches endpoints. Ingest is authenticated by the audit
	// signature regardless. Empty disables bearer auth (acceptable
	// only on loopback or behind mTLS).
	ReaderToken string
}

type acceptedBatch struct {
	Envelope      conductor.AuditBatchEnvelope `json:"envelope"`
	Payload       []byte                       `json:"payload"`
	ReceivedAt    time.Time                    `json:"received_at"`
	CanonicalHash string                       `json:"canonical_hash"`
}

type BatchSummary struct {
	BatchID          string    `json:"batch_id"`
	OrgID            string    `json:"org_id"`
	FleetID          string    `json:"fleet_id"`
	InstanceID       string    `json:"instance_id"`
	AuditSchema      int       `json:"audit_schema_version"`
	SeqStart         uint64    `json:"seq_start"`
	SeqEnd           uint64    `json:"seq_end"`
	EventCount       uint64    `json:"event_count"`
	PayloadSHA256    string    `json:"payload_sha256"`
	PayloadBytes     uint64    `json:"payload_bytes"`
	CanonicalHash    string    `json:"canonical_hash"`
	SegmentTailHash  string    `json:"segment_tail_hash"`
	DroppedCount     uint64    `json:"dropped_count"`
	EmittedAt        time.Time `json:"emitted_at"`
	ReceivedAt       time.Time `json:"received_at"`
	SignatureKeyIDs  []string  `json:"signature_key_ids"`
	InformationalDLP []string  `json:"informational_dlp,omitempty"`
}

type Query struct {
	OrgID      string
	FleetID    string
	InstanceID string
	BatchID    string
	Limit      int
}

type PutResult struct {
	Summary   BatchSummary
	Duplicate bool
}
