//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// AuditBatchQuerier exposes metadata-only audit batch queries. Implementations
// MUST NOT return raw payload bytes through this interface; raw evidence stays
// behind the storage backend's operator-controlled access boundary.
type AuditBatchQuerier interface {
	ListAuditBatches(ctx context.Context, q AuditBatchQuery) ([]AuditBatchSummary, error)
	GetAuditBatch(ctx context.Context, orgID, fleetID, instanceID, batchID string) (AuditBatchSummary, bool, error)
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

func (h *Handler) handleGetAuditBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if h.auditQuerier == nil {
		writeError(w, http.StatusNotImplemented, errors.New("audit query not supported by configured audit sink"))
		return
	}
	query, err := parseAuditBatchGetQuery(r)
	if err != nil {
		if errors.Is(err, ErrAuditBatchNotFound) {
			writeError(w, http.StatusNotFound, ErrAuditBatchNotFound)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.authorizeAuditQuery(r, query); err != nil {
		writeError(w, http.StatusForbidden, ErrAuditQueryForbidden)
		return
	}
	batch, ok, err := h.auditQuerier.GetAuditBatch(r.Context(), query.OrgID, query.FleetID, query.InstanceID, query.BatchID)
	if err != nil {
		writeAuditSinkError(w, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, ErrAuditBatchNotFound)
		return
	}
	writeJSON(w, http.StatusOK, batch)
}

func parseAuditBatchQuery(r *http.Request) (AuditBatchQuery, error) {
	values := r.URL.Query()
	if err := validateAuditQueryValues(values, "org_id", "fleet_id", "instance_id", "batch_id", "limit"); err != nil {
		return AuditBatchQuery{}, err
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
	if err := validateAuditQueryIdentifiers(q); err != nil {
		return AuditBatchQuery{}, err
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

func parseAuditBatchGetQuery(r *http.Request) (AuditBatchQuery, error) {
	batchID := strings.TrimPrefix(r.URL.Path, AuditBatchesPath+"/")
	if batchID == "" || strings.Contains(batchID, "/") {
		return AuditBatchQuery{}, ErrAuditBatchNotFound
	}
	values := r.URL.Query()
	if err := validateAuditQueryValues(values, "org_id", "fleet_id", "instance_id"); err != nil {
		return AuditBatchQuery{}, err
	}
	q := AuditBatchQuery{
		OrgID:      values.Get("org_id"),
		FleetID:    values.Get("fleet_id"),
		InstanceID: values.Get("instance_id"),
		BatchID:    batchID,
	}
	if q.OrgID == "" || q.FleetID == "" || q.InstanceID == "" {
		return AuditBatchQuery{}, errors.New("org_id, fleet_id, and instance_id query parameters required")
	}
	if err := validateAuditQueryIdentifiers(q); err != nil {
		return AuditBatchQuery{}, err
	}
	return q, nil
}

func validateAuditQueryValues(values url.Values, allowedKeys ...string) error {
	allowed := make(map[string]struct{}, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = struct{}{}
	}
	for key, got := range values {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown query parameter: %s", key)
		}
		if len(got) > 1 {
			return fmt.Errorf("duplicate query parameter: %s", key)
		}
	}
	return nil
}

func validateAuditQueryIdentifiers(q AuditBatchQuery) error {
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
			return err
		}
	}
	return nil
}
