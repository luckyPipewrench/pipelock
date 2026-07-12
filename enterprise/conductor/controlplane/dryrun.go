//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// DecisionReplayPath is the operator/dashboard endpoint that re-derives the
// conductor decision for a signed action under the current or a caller-supplied
// fleet/policy state. It is read-only: it mutates no store.
const DecisionReplayPath = "/api/v1/conductor/decision-replay"

// Emergency-control conflict codes, the emergency-store analogue of the
// publish-conflict codes. A dry-run/replay reports one of these when a
// remote-kill or rollback publish would be rejected for an operationally
// distinct, state-dependent reason (not a malformed input).
const (
	// EmergencyConflictIDConflict: the message/authorization id is already stored
	// bound to a different canonical hash.
	EmergencyConflictIDConflict = "conflict"
	// EmergencyConflictStaleCounter: the monotonic counter does not exceed the
	// highest counter already stored for this org/fleet.
	EmergencyConflictStaleCounter = "stale_counter"
	// RollbackConflictHeadPreviewFailed: the emergency authorization exists but
	// the rollback-head preview path could not re-derive the apply side.
	RollbackConflictHeadPreviewFailed = "head_preview_failed"
)

// PublishEvaluation is the read-only verdict a publish dry-run or replay reports.
// Valid is true when the publish would be accepted; when false, Conflict carries
// the machine-readable reason (a publish-conflict code or "fleet_skew"). It never
// carries bundle payload, signatures, or signing material.
type PublishEvaluation struct {
	DryRun             bool                    `json:"dry_run"`
	Valid              bool                    `json:"valid"`
	Conflict           string                  `json:"conflict,omitempty"`
	WouldCreate        bool                    `json:"would_create"`
	ResultVersion      uint64                  `json:"result_version,omitempty"`
	ResultHash         string                  `json:"result_hash,omitempty"`
	HasCurrentHead     bool                    `json:"has_current_head"`
	CurrentHeadVersion uint64                  `json:"current_head_version,omitempty"`
	CurrentHeadHash    string                  `json:"current_head_hash,omitempty"`
	Preflight          PublishPreflightSummary `json:"preflight"`
}

// RemoteKillEvaluation is the read-only verdict a remote-kill dry-run/replay
// reports.
type RemoteKillEvaluation struct {
	DryRun               bool   `json:"dry_run"`
	Valid                bool   `json:"valid"`
	Conflict             string `json:"conflict,omitempty"`
	WouldCreate          bool   `json:"would_create"`
	Counter              uint64 `json:"counter"`
	MessageHash          string `json:"message_hash,omitempty"`
	HasCurrentMaxCounter bool   `json:"has_current_max_counter"`
	CurrentMaxCounter    uint64 `json:"current_max_counter,omitempty"`
}

// RollbackEvaluation is the read-only verdict a rollback dry-run/replay reports.
// It combines the emergency-store publish decision (WouldCreate/Conflict) with
// the stream-head decision (WouldRollTo*/Noop/CurrentHead*).
type RollbackEvaluation struct {
	DryRun              bool   `json:"dry_run"`
	Valid               bool   `json:"valid"`
	Conflict            string `json:"conflict,omitempty"`
	WouldCreate         bool   `json:"would_create"`
	Counter             uint64 `json:"counter"`
	WouldRollToBundleID string `json:"would_roll_to_bundle_id,omitempty"`
	WouldRollToVersion  uint64 `json:"would_roll_to_version,omitempty"`
	WouldRollToHash     string `json:"would_roll_to_hash,omitempty"`
	Noop                bool   `json:"noop"`
	CurrentHeadVersion  uint64 `json:"current_head_version,omitempty"`
	CurrentHeadHash     string `json:"current_head_hash,omitempty"`
}

// RecordedDecision is the block a replay attaches when the supplied signed
// artifact corresponds to an action already recorded (and signature-verified) in
// the store. Present+Accepted means the store holds it; PublishedAt is when it
// was accepted. A replay never fabricates a recorded decision from the request.
type RecordedDecision struct {
	Present      bool      `json:"present"`
	Accepted     bool      `json:"accepted"`
	RecordedHash string    `json:"recorded_hash,omitempty"`
	PublishedAt  time.Time `json:"published_at,omitempty"`
}

// DecisionReplayResult is the response of the decision-replay endpoint. Exactly
// one of the three evaluation blocks is set, matching the supplied artifact kind.
// Divergence is a first-class, loud result: it is true when the re-derived
// decision under the given state does not match what was recorded, so an
// incident investigation cannot miss a silent mismatch.
//
// Honest boundary (documented on the endpoint): replay re-derives the CONDUCTOR
// authorization/effect decision for this signed action under the given
// fleet/policy state. It does NOT re-derive proxy content-scan verdicts (that is
// the deferred evidence-replay arc). A caller-supplied snapshot overrides the
// fleet-preflight dimension (roster + runtime statuses) for a publish; the store
// forward-chain, counter, and rollback-head dimensions are always evaluated
// against current store state, since they are the store's own shared decision
// logic and cannot be re-pointed at a captured chain without duplicating it.
type DecisionReplayResult struct {
	ActionKind        string                `json:"action_kind"`
	ArtifactHash      string                `json:"artifact_hash"`
	UsedStateSnapshot bool                  `json:"used_state_snapshot"`
	ReplayedAt        time.Time             `json:"replayed_at"`
	PublishEvaluation *PublishEvaluation    `json:"publish_evaluation,omitempty"`
	RemoteKill        *RemoteKillEvaluation `json:"remote_kill_evaluation,omitempty"`
	Rollback          *RollbackEvaluation   `json:"rollback_evaluation,omitempty"`
	Recorded          *RecordedDecision     `json:"recorded_decision,omitempty"`
	Divergence        bool                  `json:"divergence"`
	DivergenceReason  string                `json:"divergence_reason,omitempty"`
}

const (
	actionKindPublish    = "publish"
	actionKindRemoteKill = "remote_kill"
	actionKindRollback   = "rollback"
)

// emergencyConflictCode classifies an emergency-store publish conflict into an
// operator-facing code, mirroring publishConflictCode for the bundle store.
func emergencyConflictCode(err error) string {
	switch {
	case errors.Is(err, ErrEmergencyStaleCounter):
		return EmergencyConflictStaleCounter
	case errors.Is(err, ErrEmergencyConflict):
		return EmergencyConflictIDConflict
	default:
		return EmergencyConflictIDConflict
	}
}

// respondPublishDryRun runs the SAME fleet preflight and the SAME store publish
// decision the real apply runs, without writing, and reports the verdict. A
// determinate rejection (fleet skew or a stream/version/hash conflict) is a
// completed evaluation returned as HTTP 200 with valid=false + the reason code;
// an evaluation that cannot complete (malformed bundle, runtime-status store
// unavailable, internal error) returns the SAME error response the real path
// would (fail closed, never a false "would succeed").
func (h *Handler) respondPublishDryRun(w http.ResponseWriter, r *http.Request, bundle conductor.PolicyBundle, allowFleetSkew bool, fleetSkewReason string) {
	previewer, ok := h.store.(publishPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrDryRunUnsupported)
		return
	}
	preflight, err := h.publishPreflight(r, bundle, allowFleetSkew, fleetSkewReason)
	if err != nil {
		if errors.Is(err, ErrFleetPreflightBlocked) {
			writeJSON(w, http.StatusOK, PublishEvaluation{
				DryRun:    true,
				Valid:     false,
				Conflict:  PublishConflictFleetSkew,
				Preflight: preflight,
			})
			return
		}
		if errors.Is(err, ErrRuntimeStatusStoreRequired) {
			writeError(w, http.StatusServiceUnavailable, ErrRuntimeStatusStoreRequired)
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	preview, err := previewer.PreviewPublish(r.Context(), bundle, PublishOptions{Now: h.now()})
	if err != nil {
		if errors.Is(err, ErrBundleConflict) {
			writeJSON(w, http.StatusOK, PublishEvaluation{
				DryRun:    true,
				Valid:     false,
				Conflict:  publishConflictCode(err),
				Preflight: preflight,
			})
			return
		}
		writePublishStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, publishEvaluationFrom(preview, preflight, true))
}

func publishEvaluationFrom(preview PublishPreview, preflight PublishPreflightSummary, dryRun bool) PublishEvaluation {
	return PublishEvaluation{
		DryRun:             dryRun,
		Valid:              true,
		WouldCreate:        preview.WouldCreate,
		ResultVersion:      preview.ResultVersion,
		ResultHash:         preview.ResultHash,
		HasCurrentHead:     preview.HasCurrentHead,
		CurrentHeadVersion: preview.CurrentHeadVersion,
		CurrentHeadHash:    preview.CurrentHeadHash,
		Preflight:          preflight,
	}
}

// respondRemoteKillDryRun previews a remote-kill publish without writing. It runs
// after the same admin authorization, validity-window, and signature checks the
// real publish runs (the handler performs those before calling here).
func (h *Handler) respondRemoteKillDryRun(w http.ResponseWriter, r *http.Request, msg conductor.RemoteKillMessage, now time.Time) {
	previewer, ok := h.emergencyControls.(remoteKillPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrEmergencyPreviewUnsupported)
		return
	}
	preview, err := previewer.PreviewRemoteKill(r.Context(), msg, now)
	if err != nil {
		if errors.Is(err, ErrEmergencyConflict) || errors.Is(err, ErrEmergencyStaleCounter) {
			writeJSON(w, http.StatusOK, RemoteKillEvaluation{
				DryRun:   true,
				Valid:    false,
				Conflict: emergencyConflictCode(err),
				Counter:  msg.Counter,
			})
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, remoteKillEvaluationFrom(preview, true))
}

func remoteKillEvaluationFrom(preview RemoteKillPreview, dryRun bool) RemoteKillEvaluation {
	return RemoteKillEvaluation{
		DryRun:               dryRun,
		Valid:                true,
		WouldCreate:          preview.WouldCreate,
		Counter:              preview.Counter,
		MessageHash:          preview.MessageHash,
		HasCurrentMaxCounter: preview.HasCurrentMaxCounter,
		CurrentMaxCounter:    preview.CurrentMaxCounter,
	}
}

// respondRollbackDryRun previews BOTH would-be mutations a real rollback publish
// performs — the emergency-store authorization write AND the stream-head move —
// without writing either. The handler has already run admin authorization,
// audience validation, the validity-window check, signature verification, and
// the target-bundle-exists read before calling here.
func (h *Handler) respondRollbackDryRun(w http.ResponseWriter, r *http.Request, auth conductor.RollbackAuthorization, now time.Time) {
	authPreviewer, ok := h.emergencyControls.(rollbackAuthPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrEmergencyPreviewUnsupported)
		return
	}
	headPreviewer, ok := h.store.(rollbackHeadPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrDryRunUnsupported)
		return
	}
	authPreview, err := authPreviewer.PreviewRollbackAuthorization(r.Context(), auth, now)
	if err != nil {
		if errors.Is(err, ErrEmergencyConflict) || errors.Is(err, ErrEmergencyStaleCounter) {
			writeJSON(w, http.StatusOK, RollbackEvaluation{
				DryRun:   true,
				Valid:    false,
				Conflict: emergencyConflictCode(err),
				Counter:  auth.Counter,
			})
			return
		}
		writeStoreError(w, err)
		return
	}
	headPreview, err := headPreviewer.PreviewRollbackHead(r.Context(), auth)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rollbackEvaluationFrom(authPreview, headPreview, true))
}

func rollbackEvaluationFrom(authPreview RollbackAuthPreview, headPreview RollbackHeadPreview, dryRun bool) RollbackEvaluation {
	return RollbackEvaluation{
		DryRun:              dryRun,
		Valid:               true,
		WouldCreate:         authPreview.WouldCreate,
		Counter:             authPreview.Counter,
		WouldRollToBundleID: headPreview.WouldRollToBundleID,
		WouldRollToVersion:  headPreview.WouldRollToVersion,
		WouldRollToHash:     headPreview.WouldRollToHash,
		Noop:                headPreview.Noop,
		CurrentHeadVersion:  headPreview.CurrentHeadVersion,
		CurrentHeadHash:     headPreview.CurrentHeadHash,
	}
}

// decisionReplaySnapshot is the optional caller-supplied fleet/policy state a
// replay re-derives against. When absent, replay uses current state. Only the
// fleet-preflight dimension (Followers + RuntimeStatuses) is honored for a
// publish; see DecisionReplayResult for the documented boundary.
type decisionReplaySnapshot struct {
	Followers       []FollowerSummary       `json:"followers,omitempty"`
	RuntimeStatuses []FollowerRuntimeStatus `json:"runtime_statuses,omitempty"`
	Now             time.Time               `json:"now,omitempty"`
}

// decisionReplayRequest carries exactly one signed artifact plus an optional
// state snapshot. The strict decoder rejects unknown fields, so a caller cannot
// smuggle extra state.
type decisionReplayRequest struct {
	Bundle     *conductor.PolicyBundle          `json:"bundle,omitempty"`
	RemoteKill *conductor.RemoteKillMessage     `json:"remote_kill,omitempty"`
	Rollback   *conductor.RollbackAuthorization `json:"rollback,omitempty"`
	Snapshot   *decisionReplaySnapshot          `json:"state_snapshot,omitempty"`
}

func (h *Handler) handleDecisionReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var req decisionReplayRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	kinds := 0
	if req.Bundle != nil {
		kinds++
	}
	if req.RemoteKill != nil {
		kinds++
	}
	if req.Rollback != nil {
		kinds++
	}
	if kinds != 1 {
		writeError(w, http.StatusBadRequest, errors.New("exactly one of bundle, remote_kill, rollback is required"))
		return
	}
	if req.Snapshot != nil && req.Bundle == nil {
		writeError(w, http.StatusBadRequest, errors.New("state_snapshot is only supported for bundle replay"))
		return
	}
	now := h.now()
	if req.Snapshot != nil && !req.Snapshot.Now.IsZero() {
		now = req.Snapshot.Now.UTC()
	}
	switch {
	case req.Bundle != nil:
		h.replayPublish(w, r, *req.Bundle, req.Snapshot, now)
	case req.RemoteKill != nil:
		h.replayRemoteKill(w, r, *req.RemoteKill, now)
	default:
		h.replayRollback(w, r, *req.Rollback, now)
	}
}

func (h *Handler) replayPublish(w http.ResponseWriter, r *http.Request, bundle conductor.PolicyBundle, snapshot *decisionReplaySnapshot, now time.Time) {
	// Same authorizer as a real publish: publisher + bundle-scoped authorizer.
	if err := h.authorizePublisher(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	if err := h.authorizeBundle(r, bundle); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	previewer, ok := h.store.(publishPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrDryRunUnsupported)
		return
	}
	hash, err := bundle.CanonicalHash()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result := DecisionReplayResult{
		ActionKind:        actionKindPublish,
		ArtifactHash:      hash,
		UsedStateSnapshot: snapshot != nil,
		ReplayedAt:        now,
	}

	preflight, pfErr := h.replayPublishPreflight(r, bundle, snapshot, now)
	eval := &PublishEvaluation{}
	switch {
	case pfErr == nil:
		preview, err := previewer.PreviewPublish(r.Context(), bundle, PublishOptions{Now: now})
		if err != nil {
			if errors.Is(err, ErrBundleConflict) {
				*eval = PublishEvaluation{Valid: false, Conflict: publishConflictCode(err), Preflight: preflight}
			} else {
				writePublishStoreError(w, err)
				return
			}
		} else {
			*eval = publishEvaluationFrom(preview, preflight, false)
		}
	case errors.Is(pfErr, ErrFleetPreflightBlocked):
		*eval = PublishEvaluation{Valid: false, Conflict: PublishConflictFleetSkew, Preflight: preflight}
	case errors.Is(pfErr, ErrRuntimeStatusStoreRequired):
		writeError(w, http.StatusServiceUnavailable, ErrRuntimeStatusStoreRequired)
		return
	default:
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	result.PublishEvaluation = eval

	recorded, err := h.recordedPublish(r.Context(), bundle, hash)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	result.Recorded = recorded
	if recorded != nil && recorded.Accepted && !eval.Valid && !result.Divergence {
		result.Divergence = true
		result.DivergenceReason = "recorded as accepted but re-derived decision would reject (" + eval.Conflict + ")"
	}
	writeJSON(w, http.StatusOK, result)
}

// replayPublishPreflight evaluates the fleet preflight against a caller-supplied
// snapshot when present, or current store state otherwise. The snapshot path
// feeds the SAME pure evaluatePublishPreflight the live path funnels into, so no
// preflight logic is duplicated. Snapshot replay is strict (no fleet-skew
// override): it answers "would this have been fleet-skew-blocked as of the
// captured state".
func (h *Handler) replayPublishPreflight(r *http.Request, bundle conductor.PolicyBundle, snapshot *decisionReplaySnapshot, now time.Time) (PublishPreflightSummary, error) {
	if snapshot == nil {
		return h.publishPreflight(r, bundle, false, "")
	}
	return evaluatePublishPreflight(snapshot.Followers, snapshot.RuntimeStatuses, bundle, publishPreflightOptions{
		now:        now,
		staleAfter: defaultRuntimeStatusStaleAfter,
	})
}

// recordedPublish reports whether the store already holds the bundle's exact
// canonical hash (accepted). It looks the record up by bundle_id/version and
// compares the hash so a replay of a DIFFERENT bundle reusing an id/version is
// not falsely reported as recorded.
func (h *Handler) recordedPublish(ctx context.Context, bundle conductor.PolicyBundle, hash string) (*RecordedDecision, error) {
	record, err := h.store.BundleByIDVersion(ctx, bundle.BundleID, bundle.Version)
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if record.BundleHash != hash {
		return nil, nil
	}
	return &RecordedDecision{
		Present:      true,
		Accepted:     true,
		RecordedHash: record.BundleHash,
		PublishedAt:  record.PublishedAt,
	}, nil
}

func (h *Handler) replayRemoteKill(w http.ResponseWriter, r *http.Request, msg conductor.RemoteKillMessage, now time.Time) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	if h.emergencyKeys == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyKeyRequired)
		return
	}
	previewer, ok := h.emergencyControls.(remoteKillPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrEmergencyPreviewUnsupported)
		return
	}
	if err := validateRemoteKillControlInput(msg, h.remoteKillMaxTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	hash, err := msg.CanonicalHash()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result := DecisionReplayResult{
		ActionKind:   actionKindRemoteKill,
		ArtifactHash: hash,
		ReplayedAt:   now,
	}
	recorded, err := h.recordedRemoteKill(r.Context(), hash)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	result.Recorded = recorded
	if msg.ControlIntent() != conductor.ControlIntentReplay && (recorded == nil || !recorded.Accepted) {
		writeStoreError(w, fmt.Errorf("%w: apply-scoped remote-kill messages are not accepted by decision replay unless already recorded", conductor.ErrInvalidControlIntent))
		return
	}
	if err := msg.VerifySignaturesAt(now, h.emergencyKeys); err != nil {
		if recorded == nil || !recorded.Accepted {
			writeStoreError(w, err)
			return
		}
	}
	eval := &RemoteKillEvaluation{}
	preview, err := previewer.PreviewRemoteKill(r.Context(), msg, now)
	if err != nil {
		if errors.Is(err, ErrEmergencyConflict) || errors.Is(err, ErrEmergencyStaleCounter) {
			*eval = RemoteKillEvaluation{Valid: false, Conflict: emergencyConflictCode(err), Counter: msg.Counter}
		} else {
			writeStoreError(w, err)
			return
		}
	} else {
		*eval = remoteKillEvaluationFrom(preview, false)
	}
	result.RemoteKill = eval
	if recorded != nil && recorded.Accepted && !eval.Valid && !result.Divergence {
		result.Divergence = true
		result.DivergenceReason = "recorded as accepted but re-derived decision would reject (" + eval.Conflict + ")"
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) recordedRemoteKill(ctx context.Context, hash string) (*RecordedDecision, error) {
	if lister, ok := h.emergencyControls.(recordedRemoteKillEnumerator); ok {
		records, err := lister.RecordedRemoteKills(ctx)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if record.MessageHash == hash {
				return &RecordedDecision{
					Present:      true,
					Accepted:     true,
					RecordedHash: record.MessageHash,
					PublishedAt:  record.PublishedAt,
				}, nil
			}
		}
		return nil, nil
	}
	lister, ok := h.emergencyControls.(remoteKillEnumerator)
	if !ok {
		return nil, nil
	}
	records, err := lister.RemoteKills(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.MessageHash == hash {
			return &RecordedDecision{
				Present:      true,
				Accepted:     true,
				RecordedHash: record.MessageHash,
				PublishedAt:  record.PublishedAt,
			}, nil
		}
	}
	return nil, nil
}

func (h *Handler) replayRollback(w http.ResponseWriter, r *http.Request, auth conductor.RollbackAuthorization, now time.Time) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	if h.emergencyKeys == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyKeyRequired)
		return
	}
	authPreviewer, ok := h.emergencyControls.(rollbackAuthPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrEmergencyPreviewUnsupported)
		return
	}
	headPreviewer, ok := h.store.(rollbackHeadPreviewer)
	if !ok {
		writeError(w, http.StatusInternalServerError, ErrDryRunUnsupported)
		return
	}
	if err := validateRollbackControlInput(auth, h.rollbackMaxTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	hash, err := auth.CanonicalHash()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result := DecisionReplayResult{
		ActionKind:   actionKindRollback,
		ArtifactHash: hash,
		ReplayedAt:   now,
	}
	recorded, err := h.recordedRollback(r.Context(), hash)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	result.Recorded = recorded
	if auth.ControlIntent() != conductor.ControlIntentReplay && (recorded == nil || !recorded.Accepted) {
		writeStoreError(w, fmt.Errorf("%w: apply-scoped rollback authorizations are not accepted by decision replay unless already recorded", conductor.ErrInvalidControlIntent))
		return
	}
	if err := auth.VerifySignaturesAt(now, h.emergencyKeys); err != nil {
		if recorded == nil || !recorded.Accepted {
			writeStoreError(w, err)
			return
		}
	}
	eval := &RollbackEvaluation{}
	authPreview, err := authPreviewer.PreviewRollbackAuthorization(r.Context(), auth, now)
	switch {
	case err == nil:
		headPreview, headErr := headPreviewer.PreviewRollbackHead(r.Context(), auth)
		if headErr != nil {
			if recorded == nil || !recorded.Accepted {
				writeStoreError(w, headErr)
				return
			}
			// Do not serialize the store error into the response: backend
			// errors can carry paths/keys/operational internals. Return a
			// stable reason plus the structured conflict code, log details
			// server-side.
			if h.logger != nil {
				h.logger.ErrorContext(r.Context(), "conductor_rollback_replay_head_preview_failed", slog.String("error", headErr.Error()))
			}
			*eval = RollbackEvaluation{Valid: false, Conflict: RollbackConflictHeadPreviewFailed, Counter: auth.Counter}
			result.Divergence = true
			result.DivergenceReason = "recorded as accepted but rollback head preview failed"
			break
		}
		*eval = rollbackEvaluationFrom(authPreview, headPreview, false)
	case errors.Is(err, ErrEmergencyConflict) || errors.Is(err, ErrEmergencyStaleCounter):
		*eval = RollbackEvaluation{Valid: false, Conflict: emergencyConflictCode(err), Counter: auth.Counter}
	default:
		writeStoreError(w, err)
		return
	}
	result.Rollback = eval
	if recorded != nil && recorded.Accepted && !eval.Valid && !result.Divergence {
		result.Divergence = true
		result.DivergenceReason = "recorded as accepted but re-derived decision would reject (" + eval.Conflict + ")"
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) recordedRollback(ctx context.Context, hash string) (*RecordedDecision, error) {
	if lister, ok := h.emergencyControls.(recordedRollbackAuthorizationEnumerator); ok {
		records, err := lister.RecordedRollbackAuthorizations(ctx)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if record.AuthorizationHash == hash {
				return &RecordedDecision{
					Present:      true,
					Accepted:     true,
					RecordedHash: record.AuthorizationHash,
					PublishedAt:  record.PublishedAt,
				}, nil
			}
		}
		return nil, nil
	}
	lister, ok := h.emergencyControls.(rollbackAuthorizationEnumerator)
	if !ok {
		return nil, nil
	}
	records, err := lister.RollbackAuthorizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.AuthorizationHash == hash {
			return &RecordedDecision{
				Present:      true,
				Accepted:     true,
				RecordedHash: record.AuthorizationHash,
				PublishedAt:  record.PublishedAt,
			}, nil
		}
	}
	return nil, nil
}
