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
	Followers []FollowerFleetStatus `json:"followers"`
	Count     int                   `json:"count"`
}

// handleListFollowers serves the admin/auditor follower-roster read. It mirrors
// the audit-query handler: a strict, allowlisted query-parameter set; a
// mandatory org_id so the read is never globally unscoped; identifier
// validation; then an authorizer that binds the caller's credential scope to
// the requested org/fleet BEFORE the store is touched.
func (h *Handler) handleListFollowers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleGetFollowers(w, r)
	case http.MethodDelete:
		h.handleRemoveFollower(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodDelete)
	}
}

func (h *Handler) handleGetFollowers(w http.ResponseWriter, r *http.Request) {
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
	enriched, err := h.enrichFollowerStatus(r, query, followers)
	if err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "conductor_followers_runtime_status_failed",
				slog.String("event", "conductor_followers_runtime_status_failed"),
				slog.String("error", err.Error()),
				slog.String("org_id", query.OrgID),
				slog.String("fleet_id", query.FleetID),
				slog.String("instance_id", query.InstanceID),
			)
		}
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	if enriched == nil {
		enriched = []FollowerFleetStatus{}
	}
	writeJSON(w, http.StatusOK, listFollowersResponse{
		Followers: enriched,
		Count:     len(enriched),
	})
}

func (h *Handler) enrichFollowerStatus(r *http.Request, query FollowerListQuery, followers []FollowerSummary) ([]FollowerFleetStatus, error) {
	if followers == nil {
		followers = []FollowerSummary{}
	}
	now := h.now()
	var streams []StreamSummary
	if query.OrgID != "" {
		var err error
		streams, err = h.store.StreamOverview(r.Context(), StreamStatusQuery{OrgID: query.OrgID, FleetID: query.FleetID})
		if err != nil {
			return nil, err
		}
	}
	var statusByID map[string]FollowerRuntimeStatus
	if statusStore, ok := h.enrollments.(RuntimeStatusStore); ok && statusStore != nil {
		statuses, err := statusStore.ListFollowerRuntimeStatus(r.Context(), RuntimeStatusQuery{
			OrgID:      query.OrgID,
			FleetID:    query.FleetID,
			InstanceID: query.InstanceID,
			Limit:      maxFollowerListLimit,
		})
		if err != nil {
			return nil, err
		}
		statusByID = runtimeStatusMap(statuses)
	}
	signedByID, err := h.verifiedAppliedStateMap(r, query)
	if err != nil {
		return nil, err
	}
	out := make([]FollowerFleetStatus, 0, len(followers))
	for _, follower := range followers {
		var statusPtr *FollowerRuntimeStatus
		if statusByID != nil {
			if status, ok := statusByID[followerEnrollmentKey(FollowerIdentity{
				OrgID:       follower.OrgID,
				FleetID:     follower.FleetID,
				InstanceID:  follower.InstanceID,
				Environment: follower.Environment,
			})]; ok {
				statusCopy := status
				statusPtr = &statusCopy
			}
		}
		var signedPtr *VerifiedAppliedState
		if signed, ok := signedByID[verifiedAppliedStateKey(follower.OrgID, follower.FleetID, follower.InstanceID)]; ok {
			signedCopy := signed
			signedPtr = &signedCopy
		}
		expected := expectedBundleForFollower(streams, follower, now)
		health, drift := classifyFollowerHealth(follower, statusPtr, expected, now, defaultRuntimeStatusStaleAfter)
		out = append(out, FollowerFleetStatus{
			FollowerSummary:    follower,
			RuntimeStatus:      statusPtr,
			SignedAppliedState: signedPtr,
			Health:             health,
			Drift:              drift,
			ExpectedBundle:     expected,
		})
	}
	return out, nil
}

// verifiedAppliedStateMap loads the signed, verified applied-state for the
// queried scope keyed by (org, fleet, instance). It is best-effort: a
// deployment whose audit sink does not implement the reader (or has no rows)
// simply yields no signed state, and followers fall back to unsigned runtime
// status.
func (h *Handler) verifiedAppliedStateMap(r *http.Request, query FollowerListQuery) (map[string]VerifiedAppliedState, error) {
	reader, ok := h.auditSink.(VerifiedAppliedStateReader)
	if !ok || reader == nil {
		return nil, nil
	}
	states, err := reader.ListVerifiedAppliedState(r.Context(), VerifiedAppliedStateQuery{
		OrgID:      query.OrgID,
		FleetID:    query.FleetID,
		InstanceID: query.InstanceID,
		Limit:      maxFollowerListLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]VerifiedAppliedState, len(states))
	for _, state := range states {
		out[verifiedAppliedStateKey(state.OrgID, state.FleetID, state.InstanceID)] = state
	}
	return out, nil
}

// verifiedAppliedStateKey keys signed applied-state by the audit-path identity
// (org, fleet, instance). The audit envelope carries no environment, so unlike
// followerEnrollmentKey this identity is environment-independent.
func verifiedAppliedStateKey(orgID, fleetID, instanceID string) string {
	return orgID + "\x00" + fleetID + "\x00" + instanceID
}

type removeFollowerRequest struct {
	OrgID       string `json:"org_id"`
	FleetID     string `json:"fleet_id"`
	InstanceID  string `json:"instance_id"`
	Environment string `json:"environment"`
}

func (h *Handler) handleRemoveFollower(w http.ResponseWriter, r *http.Request) {
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	var req removeFollowerRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	identity := FollowerIdentity{
		OrgID:       req.OrgID,
		FleetID:     req.FleetID,
		InstanceID:  req.InstanceID,
		Environment: req.Environment,
	}
	if err := identity.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	summary, err := h.enrollments.RemoveEnrolledFollower(r.Context(), RemoveEnrolledFollowerRequest{
		Identity: identity,
		Now:      h.now(),
	})
	if err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "conductor_follower_remove_failed",
				slog.String("event", "conductor_follower_remove_failed"),
				slog.String("error", err.Error()),
				slog.String("org_id", identity.OrgID),
				slog.String("fleet_id", identity.FleetID),
				slog.String("instance_id", identity.InstanceID),
			)
		}
		writeEnrollmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
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
