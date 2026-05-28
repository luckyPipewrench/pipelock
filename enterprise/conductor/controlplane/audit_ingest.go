//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// AuditKeyResolver resolves follower audit signing keys from the authenticated
// follower identity. Production implementations MUST only return keys enrolled
// for that exact org/fleet/instance tuple. A resolver that returns a fleet-wide
// or org-wide audit key would let any enrolled instance impersonate any other
// instance in the same scope: the identity binding check in
// validateAuditBatchForIdentity rejects envelopes whose claimed identity does
// not match the authenticated transport identity, but it cannot detect a
// resolver that hands out shared signing material. The resolver is the only
// place this guarantee can be enforced.
//
// Resolver error text MUST be considered a roster-internal detail; the handler
// strips it from client responses by mapping all signature failures to a
// canonical [conductor.ErrSignatureVerification], but the resolver itself
// should still avoid putting secret material into its error messages in case
// future code paths log them.
type AuditKeyResolver func(FollowerIdentity, string) (conductor.SignatureKey, error)

// AuditBatchSink receives audit batches after transport identity, payload hash,
// clock skew, and follower audit-batch signature checks have all passed.
//
// This MVP layer does NOT deduplicate batches. A previously accepted signed
// envelope presented again with the same authenticated follower identity can be
// accepted up to [conductor.DefaultAuditMaxSkew] after its EmittedAt timestamp
// (skew is the only at-this-layer replay defense).
// Sinks that need exactly-once semantics, such as durable central storage, fork
// detection, or indexing, MUST implement their own idempotency on
// (BatchID, EnvelopeHash) or (OrgID, FleetID, InstanceID, SeqStart, SeqEnd).
// Each accepted batch arrives with a fresh Payload copy detached from the
// request body, so sinks may retain the slice without further copying.
type AuditBatchSink interface {
	IngestAuditBatch(context.Context, AcceptedAuditBatch) error
}

type AcceptedAuditBatch struct {
	Identity     FollowerIdentity
	Envelope     conductor.AuditBatchEnvelope
	EnvelopeHash string
	Payload      []byte
	ReceivedAt   time.Time
}

type ingestAuditBatchRequest struct {
	Envelope conductor.AuditBatchEnvelope `json:"envelope"`
	Payload  []byte                       `json:"payload"`
}

type ingestAuditBatchResponse struct {
	BatchID      string    `json:"batch_id"`
	EnvelopeHash string    `json:"envelope_hash"`
	SeqStart     uint64    `json:"seq_start"`
	SeqEnd       uint64    `json:"seq_end"`
	AcceptedAt   time.Time `json:"accepted_at"`
}

func (h *Handler) handleAuditBatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListAuditBatches(w, r)
		return
	case http.MethodPost:
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	if err := identity.Validate(); err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	var req ingestAuditBatchRequest
	if err := decodeStrictJSON(w, r, h.maxAuditBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	acceptedAt := h.now()
	if err := validateAuditBatchForIdentity(req.Envelope, req.Payload, identity, acceptedAt, h.auditKeys); err != nil {
		writeAuditIngestError(w, err)
		return
	}
	envelopeHash, err := req.Envelope.CanonicalHash()
	if err != nil {
		writeAuditIngestError(w, err)
		return
	}
	if err := h.auditSink.IngestAuditBatch(r.Context(), AcceptedAuditBatch{
		Identity:     identity,
		Envelope:     req.Envelope,
		EnvelopeHash: envelopeHash,
		Payload:      append([]byte(nil), req.Payload...),
		ReceivedAt:   acceptedAt,
	}); err != nil {
		writeAuditSinkError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, ingestAuditBatchResponse{
		BatchID:      req.Envelope.BatchID,
		EnvelopeHash: envelopeHash,
		SeqStart:     req.Envelope.SeqStart,
		SeqEnd:       req.Envelope.SeqEnd,
		AcceptedAt:   acceptedAt,
	})
}

func validateAuditBatchForIdentity(
	envelope conductor.AuditBatchEnvelope,
	payload []byte,
	identity FollowerIdentity,
	now time.Time,
	resolve AuditKeyResolver,
) error {
	if envelope.OrgID != identity.OrgID || envelope.FleetID != identity.FleetID || envelope.InstanceID != identity.InstanceID {
		return conductor.ErrAudienceMismatch
	}
	if err := envelope.ValidateForConductorWithPayload(now, conductor.DefaultAuditMaxSkew, payload); err != nil {
		return err
	}
	return envelope.VerifySignaturesAt(now, func(signerKeyID string) (conductor.SignatureKey, error) {
		return resolve(identity, signerKeyID)
	})
}

// writeAuditSinkError maps errors returned by an AuditBatchSink implementation
// (e.g. SQLiteAuditStore) to the right HTTP status. Sinks may re-run
// defensive validation that the handler already performed (envelope/identity
// audience binding, envelope hash, payload hash), so the same error types
// surface here. Without this classification a conflicting batch_id or a
// detected sequence fork would arrive as HTTP 500, prompting follower clients
// to treat a permanent rejection as transient and retry forever.
func writeAuditSinkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAuditBatchConflict):
		writeError(w, http.StatusConflict, ErrAuditBatchConflict)
	case errors.Is(err, ErrAuditForkDetected):
		writeError(w, http.StatusConflict, ErrAuditForkDetected)
	case errors.Is(err, ErrInvalidStoreRecord):
		writeError(w, http.StatusBadRequest, ErrInvalidStoreRecord)
	case errors.Is(err, ErrFollowerRequired):
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
	default:
		writeAuditIngestError(w, err)
	}
}

func writeAuditIngestError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, conductor.ErrAudienceMismatch):
		writeError(w, http.StatusForbidden, conductor.ErrAudienceMismatch)
	case errors.Is(err, conductor.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
	case errors.Is(err, conductor.ErrHashMismatch),
		errors.Is(err, conductor.ErrExpired),
		errors.Is(err, conductor.ErrNotYetValid),
		errors.Is(err, conductor.ErrSkewExceeded):
		writeError(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, conductor.ErrInvalidSignature),
		errors.Is(err, conductor.ErrWrongKeyPurpose),
		errors.Is(err, conductor.ErrThresholdRequired),
		errors.Is(err, conductor.ErrSignatureVerification):
		writeError(w, http.StatusUnauthorized, conductor.ErrSignatureVerification)
	case errors.Is(err, conductor.ErrUnsupportedSchemaVersion),
		errors.Is(err, conductor.ErrMissingField),
		errors.Is(err, conductor.ErrInvalidHash),
		errors.Is(err, conductor.ErrInvalidSequenceRange),
		errors.Is(err, conductor.ErrInvalidDroppedAccounting),
		errors.Is(err, conductor.ErrInvalidIdentifier):
		writeError(w, http.StatusBadRequest, err)
	default:
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}
