//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

type listFollowersResponse struct {
	Followers []FollowerSummary `json:"followers"`
	Count     int               `json:"count"`
}

// handleListFollowers serves the admin/auditor follower-roster read. It mirrors
// the audit-query handler: a strict, allowlisted query-parameter set; a
// mandatory org_id so the read is never globally unscoped; identifier
// validation; then an authorizer that binds the caller's credential scope to
// the requested org/fleet BEFORE the store is touched.
func (h *Handler) handleListFollowers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	query, err := parseFollowerListQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.authorizeFollowers(r, query); err != nil {
		writeError(w, http.StatusForbidden, ErrFollowerListForbidden)
		return
	}
	followers, err := h.enrollments.ListEnrolledFollowers(r.Context(), query)
	if err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "conductor_followers_list_failed",
				slog.String("event", "conductor_followers_list_failed"),
				slog.String("error", err.Error()),
				slog.String("org_id", query.OrgID),
				slog.String("fleet_id", query.FleetID),
				slog.String("instance_id", query.InstanceID),
			)
		}
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	if followers == nil {
		followers = []FollowerSummary{}
	}
	writeJSON(w, http.StatusOK, listFollowersResponse{
		Followers: followers,
		Count:     len(followers),
	})
}

func parseFollowerListQuery(r *http.Request) (FollowerListQuery, error) {
	values := r.URL.Query()
	if err := validateFollowerListValues(values, "org_id", "fleet_id", "instance_id", "limit"); err != nil {
		return FollowerListQuery{}, err
	}
	q := FollowerListQuery{
		OrgID:      values.Get("org_id"),
		FleetID:    values.Get("fleet_id"),
		InstanceID: values.Get("instance_id"),
	}
	if q.OrgID == "" {
		return FollowerListQuery{}, errors.New("org_id query parameter required")
	}
	if err := validateFollowerListIdentifiers(q); err != nil {
		return FollowerListQuery{}, err
	}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 || limit > maxFollowerListLimit {
			return FollowerListQuery{}, fmt.Errorf("invalid limit query parameter: %q (must be 1..%d)", rawLimit, maxFollowerListLimit)
		}
		q.Limit = limit
	}
	return q, nil
}

func validateFollowerListValues(values url.Values, allowedKeys ...string) error {
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

func validateFollowerListIdentifiers(q FollowerListQuery) error {
	for _, c := range []struct {
		field, value string
	}{
		{"org_id", q.OrgID},
		{"fleet_id", q.FleetID},
		{"instance_id", q.InstanceID},
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
