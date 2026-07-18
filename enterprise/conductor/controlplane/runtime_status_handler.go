//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

type runtimeStatusRequest struct {
	Status FollowerRuntimeStatus `json:"status"`
}

type runtimeStatusResponse struct {
	Status FollowerRuntimeStatus `json:"status"`
}

func (h *Handler) handleFollowerRuntimeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	store, ok := h.enrollments.(RuntimeStatusStore)
	if !ok || store == nil {
		writeError(w, http.StatusNotImplemented, ErrRuntimeStatusStoreRequired)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	var req runtimeStatusRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !sameFollowerIdentity(identity, req.Status.Identity()) {
		writeError(w, http.StatusForbidden, ErrRuntimeStatusIdentityMismatch)
		return
	}
	req.Status.LastSeenAt = h.now()
	status, err := store.UpsertFollowerRuntimeStatus(r.Context(), req.Status)
	if err != nil {
		if h.logger != nil {
			h.logger.WarnContext(r.Context(), "conductor_runtime_status_rejected",
				slog.String("event", "conductor_runtime_status_rejected"),
				slog.String("error", err.Error()),
				slog.String("org_id", identity.OrgID),
				slog.String("fleet_id", identity.FleetID),
				slog.String("instance_id", identity.InstanceID),
			)
		}
		writeRuntimeStatusError(w, err)
		return
	}
	if h.logger != nil {
		h.logger.DebugContext(r.Context(), "conductor_runtime_status_accepted",
			slog.String("event", "conductor_runtime_status_accepted"),
			slog.String("org_id", identity.OrgID),
			slog.String("fleet_id", identity.FleetID),
			slog.String("instance_id", identity.InstanceID),
			slog.String("pipelock_version", status.PipelockVersion),
			slog.String("git_commit", status.GitCommit),
			slog.String("active_bundle_id", status.ActiveBundleID),
			slog.Uint64("active_bundle_version", status.ActiveBundleVersion),
			slog.String("active_bundle_hash", status.ActiveBundleHash),
			slog.String("last_apply_error_code", status.LastApplyErrorCode),
		)
	}
	writeJSON(w, http.StatusOK, runtimeStatusResponse{Status: status})
}

func writeRuntimeStatusError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFollowerNotFound):
		writeError(w, http.StatusForbidden, ErrFollowerNotFound)
	case errors.Is(err, ErrRuntimeStatusLimitExceeded), errors.Is(err, conductor.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, err)
	case errors.Is(err, conductor.ErrInvalidIdentifier), errors.Is(err, conductor.ErrInvalidHash):
		writeError(w, http.StatusBadRequest, err)
	default:
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}
