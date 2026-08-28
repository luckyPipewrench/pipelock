//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

var ErrAppliedStateReplay = errors.New("conductor applied-state heartbeat is not newer than verified state")

type AcceptedAppliedStateHeartbeat struct {
	Identity      FollowerIdentity
	Heartbeat     conductor.AppliedStateHeartbeat
	HeartbeatHash string
	ReceivedAt    time.Time
}

type AppliedStateHeartbeatStatus string

const (
	AppliedStateHeartbeatAccepted  AppliedStateHeartbeatStatus = "accepted"
	AppliedStateHeartbeatDuplicate AppliedStateHeartbeatStatus = "duplicate"
)

type AppliedStateHeartbeatSink interface {
	IngestAppliedStateHeartbeat(context.Context, AcceptedAppliedStateHeartbeat) (AppliedStateHeartbeatStatus, error)
}

func (h *Handler) handleAppliedStateHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if h.capabilities.AuditBatch.Max < conductor.AppliedStateHeartbeatSchemaVersion {
		writeError(w, http.StatusNotImplemented, conductor.ErrUnsupportedSchemaVersion)
		return
	}
	sink, ok := h.auditSink.(AppliedStateHeartbeatSink)
	if !ok || sink == nil {
		writeError(w, http.StatusNotImplemented, ErrAuditSinkRequired)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil || identity.Validate() != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	var heartbeat conductor.AppliedStateHeartbeat
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &heartbeat); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	acceptedAt := h.now()
	if heartbeat.OrgID != identity.OrgID || heartbeat.FleetID != identity.FleetID || heartbeat.InstanceID != identity.InstanceID {
		writeAuditIngestError(w, conductor.ErrAudienceMismatch)
		return
	}
	if err := heartbeat.ValidateForConductor(acceptedAt, conductor.DefaultAuditMaxSkew); err != nil {
		writeAuditIngestError(w, err)
		return
	}
	if err := heartbeat.VerifySignaturesAt(acceptedAt, func(signerKeyID string) (conductor.SignatureKey, error) {
		return h.auditKeys(identity, signerKeyID)
	}); err != nil {
		writeAuditIngestError(w, err)
		return
	}
	heartbeatHash, err := heartbeat.CanonicalHash()
	if err != nil {
		writeAuditIngestError(w, err)
		return
	}
	status, err := sink.IngestAppliedStateHeartbeat(r.Context(), AcceptedAppliedStateHeartbeat{
		Identity:      identity,
		Heartbeat:     heartbeat,
		HeartbeatHash: heartbeatHash,
		ReceivedAt:    acceptedAt,
	})
	if err != nil {
		if errors.Is(err, ErrAppliedStateReplay) {
			writeError(w, http.StatusConflict, ErrAppliedStateReplay)
			return
		}
		writeAuditSinkError(w, err)
		return
	}
	if status == "" {
		status = AppliedStateHeartbeatAccepted
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":         status,
		"heartbeat_id":   heartbeat.HeartbeatID,
		"heartbeat_hash": heartbeatHash,
		"accepted_at":    acceptedAt.UTC(),
	})
}
