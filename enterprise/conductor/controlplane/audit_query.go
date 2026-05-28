//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// AuditBatchQuerier exposes metadata-only audit batch queries. Implementations
// MUST NOT return raw payload bytes through this interface; raw evidence stays
// behind the storage backend's operator-controlled access boundary.
type AuditBatchQuerier interface {
	ListAuditBatches(ctx context.Context, q AuditBatchQuery) ([]AuditBatchSummary, error)
}

type listAuditBatchesResponse struct {
	Batches []AuditBatchSummary `json:"batches"`
	Count   int                 `json:"count"`
}

// handleListAuditBatches serves operator/admin audit-metadata reads.
func (h *Handler) handleListAuditBatches(w http.ResponseWriter, r *http.Request) {
	if h.auditQuerier == nil {
		writeError(w, http.StatusNotImplemented, errors.New("audit query not supported by configured audit sink"))
		return
	}
	query, err := parseAuditBatchQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.authorizeAuditQuery(r, query); err != nil {
		writeError(w, http.StatusForbidden, ErrAuditQueryForbidden)
		return
	}
	batches, err := h.auditQuerier.ListAuditBatches(r.Context(), query)
	if err != nil {
		writeAuditSinkError(w, err)
		return
	}
	if batches == nil {
		batches = []AuditBatchSummary{}
	}
	writeJSON(w, http.StatusOK, listAuditBatchesResponse{
		Batches: batches,
		Count:   len(batches),
	})
}

func parseAuditBatchQuery(r *http.Request) (AuditBatchQuery, error) {
	values := r.URL.Query()
	for key, got := range values {
		switch key {
		case "org_id", "fleet_id", "instance_id", "batch_id", "limit":
		default:
			return AuditBatchQuery{}, fmt.Errorf("unknown query parameter: %s", key)
		}
		if len(got) > 1 {
			return AuditBatchQuery{}, fmt.Errorf("duplicate query parameter: %s", key)
		}
	}
	q := AuditBatchQuery{
		OrgID:      values.Get("org_id"),
		FleetID:    values.Get("fleet_id"),
		InstanceID: values.Get("instance_id"),
		BatchID:    values.Get("batch_id"),
	}
	if q.OrgID == "" {
		return AuditBatchQuery{}, errors.New("org_id query parameter required")
	}
	for _, c := range []struct {
		field, value string
	}{
		{"org_id", q.OrgID},
		{"fleet_id", q.FleetID},
		{"instance_id", q.InstanceID},
		{"batch_id", q.BatchID},
	} {
		if c.value == "" {
			continue
		}
		if err := conductor.ValidateIdentifier(c.field, c.value); err != nil {
			return AuditBatchQuery{}, err
		}
	}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 {
			return AuditBatchQuery{}, fmt.Errorf("invalid limit query parameter: %q", rawLimit)
		}
		q.Limit = limit
	}
	return q, nil
}
