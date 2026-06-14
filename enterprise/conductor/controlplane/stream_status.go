//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// remoteKillEnumerator is the read-only interface the stream-status handler uses
// to enumerate stored remote-kill records. It mirrors the private
// rollbackAuthorizationEnumerator interface used by startup reconciliation, so
// an EmergencyStore that does not implement enumeration degrades to "no active
// kills reported" rather than failing the read.
type remoteKillEnumerator interface {
	RemoteKills(context.Context) ([]StoredRemoteKill, error)
}

// ActiveRemoteKill is the operator-facing view of one currently-valid remote
// kill scoped to the queried org/fleet.
type ActiveRemoteKill struct {
	MessageID   string                    `json:"message_id"`
	MessageHash string                    `json:"message_hash"`
	OrgID       string                    `json:"org_id"`
	FleetID     string                    `json:"fleet_id"`
	Audience    conductor.Audience        `json:"audience"`
	State       conductor.KillSwitchState `json:"state"`
	Counter     uint64                    `json:"counter"`
	Reason      string                    `json:"reason"`
	NotBefore   time.Time                 `json:"not_before"`
	ExpiresAt   time.Time                 `json:"expires_at"`
	PublishedAt time.Time                 `json:"published_at"`
}

// ActiveRollbackAuthorization is the operator-facing view of one currently-valid
// rollback authorization scoped to the queried org/fleet.
type ActiveRollbackAuthorization struct {
	AuthorizationID   string             `json:"authorization_id"`
	AuthorizationHash string             `json:"authorization_hash"`
	OrgID             string             `json:"org_id"`
	FleetID           string             `json:"fleet_id"`
	Audience          conductor.Audience `json:"audience"`
	CurrentBundleID   string             `json:"current_bundle_id"`
	CurrentVersion    uint64             `json:"current_version"`
	TargetBundleID    string             `json:"target_bundle_id"`
	TargetVersion     uint64             `json:"target_version"`
	Counter           uint64             `json:"counter"`
	Reason            string             `json:"reason"`
	CreatedAt         time.Time          `json:"created_at"`
	ExpiresAt         time.Time          `json:"expires_at"`
	PublishedAt       time.Time          `json:"published_at"`
}

// streamStatusResponse is the full operator stream-overview payload. It reports
// stream topology, the monotonicity gate, the bundle chain, and the active
// emergency controls in scope. It intentionally carries NO per-follower applied
// version or drift: the Conductor enrollment store does not track per-follower
// applied bundle version, so reporting it would be a fabrication. Follower
// applied state is not available here; the follower roster count is the only
// follower-derived figure, and it is reported by `conductor fleet status`.
type streamStatusResponse struct {
	OrgID                 string                        `json:"org_id"`
	FleetID               string                        `json:"fleet_id,omitempty"`
	Streams               []StreamSummary               `json:"streams"`
	StreamCount           int                           `json:"stream_count"`
	ActiveRemoteKills     []ActiveRemoteKill            `json:"active_remote_kills"`
	ActiveRollbacks       []ActiveRollbackAuthorization `json:"active_rollback_authorizations"`
	EmergencyControlsRead bool                          `json:"emergency_controls_read"`
}

// handleStreamStatus serves the admin/auditor stream-overview read. It mirrors
// the follower-roster handler: a strict, allowlisted query-parameter set; a
// mandatory org_id so the read is never globally unscoped; identifier
// validation; then an authorizer that binds the caller's credential scope to
// the requested org/fleet BEFORE the store is touched. The response reports
// stream topology only and never claims per-follower applied version or drift.
func (h *Handler) handleStreamStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	query, err := parseStreamStatusQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := h.authorizeStream(r, query); err != nil {
		writeError(w, http.StatusForbidden, ErrStreamStatusForbidden)
		return
	}
	streams, err := h.store.StreamOverview(r.Context(), query)
	if err != nil {
		h.logStreamStatusFailure(r, query, "conductor_stream_overview_failed", err)
		writeStoreError(w, err)
		return
	}
	if streams == nil {
		streams = []StreamSummary{}
	}
	now := h.now()
	kills, rollbacks, emergencyRead, err := h.activeEmergencyControls(r.Context(), query, now)
	if err != nil {
		h.logStreamStatusFailure(r, query, "conductor_stream_emergency_read_failed", err)
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	writeJSON(w, http.StatusOK, streamStatusResponse{
		OrgID:                 query.OrgID,
		FleetID:               query.FleetID,
		Streams:               streams,
		StreamCount:           len(streams),
		ActiveRemoteKills:     kills,
		ActiveRollbacks:       rollbacks,
		EmergencyControlsRead: emergencyRead,
	})
}

// activeEmergencyControls reads the active remote kills and rollback
// authorizations in scope. It reuses the same EmergencyStore enumerators that
// startup reconciliation and the operator read paths use, applies the queried
// org/fleet scope, and drops records that are not currently valid at now. The
// emergencyRead return reports whether the configured store supports
// enumeration; a store without enumeration yields empty slices rather than an
// error, so an older EmergencyStore degrades to "no active controls reported".
func (h *Handler) activeEmergencyControls(ctx context.Context, q StreamStatusQuery, now time.Time) ([]ActiveRemoteKill, []ActiveRollbackAuthorization, bool, error) {
	kills := []ActiveRemoteKill{}
	rollbacks := []ActiveRollbackAuthorization{}
	if h.emergencyControls == nil {
		return kills, rollbacks, false, nil
	}
	read := false
	if killLister, ok := h.emergencyControls.(remoteKillEnumerator); ok {
		read = true
		records, err := killLister.RemoteKills(ctx)
		if err != nil {
			return nil, nil, false, err
		}
		for _, record := range records {
			msg := record.Message
			if !emergencyInScope(msg.OrgID, msg.FleetID, q) {
				continue
			}
			if err := msg.ValidateAtTime(now); err != nil {
				continue
			}
			if msg.State != conductor.KillSwitchActive {
				continue
			}
			kills = append(kills, ActiveRemoteKill{
				MessageID:   msg.MessageID,
				MessageHash: record.MessageHash,
				OrgID:       msg.OrgID,
				FleetID:     msg.FleetID,
				Audience:    msg.Audience,
				State:       msg.State,
				Counter:     msg.Counter,
				Reason:      msg.Reason,
				NotBefore:   msg.NotBefore,
				ExpiresAt:   msg.ExpiresAt,
				PublishedAt: record.PublishedAt,
			})
		}
	}
	if rollbackLister, ok := h.emergencyControls.(rollbackAuthorizationEnumerator); ok {
		read = true
		records, err := rollbackLister.RollbackAuthorizations(ctx)
		if err != nil {
			return nil, nil, false, err
		}
		for _, record := range records {
			auth := record.Authorization
			if !emergencyInScope(auth.OrgID, auth.FleetID, q) {
				continue
			}
			if err := auth.ValidateAtTime(now); err != nil {
				continue
			}
			rollbacks = append(rollbacks, ActiveRollbackAuthorization{
				AuthorizationID:   auth.AuthorizationID,
				AuthorizationHash: record.AuthorizationHash,
				OrgID:             auth.OrgID,
				FleetID:           auth.FleetID,
				Audience:          auth.Audience,
				CurrentBundleID:   auth.CurrentBundleID,
				CurrentVersion:    auth.CurrentVersion,
				TargetBundleID:    auth.TargetBundleID,
				TargetVersion:     auth.TargetVersion,
				Counter:           auth.Counter,
				Reason:            auth.Reason,
				CreatedAt:         auth.CreatedAt,
				ExpiresAt:         auth.ExpiresAt,
				PublishedAt:       record.PublishedAt,
			})
		}
	}
	return kills, rollbacks, read, nil
}

// emergencyInScope reports whether an org/fleet-keyed emergency control matches
// the queried scope: the org must match exactly, and when a fleet is requested
// the fleet must match exactly too.
func emergencyInScope(orgID, fleetID string, q StreamStatusQuery) bool {
	if orgID != q.OrgID {
		return false
	}
	if q.FleetID != "" && fleetID != q.FleetID {
		return false
	}
	return true
}

func (h *Handler) logStreamStatusFailure(r *http.Request, q StreamStatusQuery, event string, err error) {
	if h.logger == nil {
		return
	}
	h.logger.ErrorContext(r.Context(), event,
		slog.String("event", event),
		slog.String("error", err.Error()),
		slog.String("org_id", q.OrgID),
		slog.String("fleet_id", q.FleetID),
	)
}

func parseStreamStatusQuery(r *http.Request) (StreamStatusQuery, error) {
	values := r.URL.Query()
	if err := validateStreamStatusValues(values, "org_id", "fleet_id"); err != nil {
		return StreamStatusQuery{}, err
	}
	q := StreamStatusQuery{
		OrgID:   values.Get("org_id"),
		FleetID: values.Get("fleet_id"),
	}
	if q.OrgID == "" {
		return StreamStatusQuery{}, errors.New("org_id query parameter required")
	}
	if err := conductor.ValidateIdentifier("org_id", q.OrgID); err != nil {
		return StreamStatusQuery{}, err
	}
	if q.FleetID != "" {
		if err := conductor.ValidateIdentifier("fleet_id", q.FleetID); err != nil {
			return StreamStatusQuery{}, err
		}
	}
	return q, nil
}

func validateStreamStatusValues(values url.Values, allowedKeys ...string) error {
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
