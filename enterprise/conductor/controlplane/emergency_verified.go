//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"log/slog"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// Quarantine audit event names. A quarantine is a high-severity event: a stored
// emergency-control record that passed structural validation at load
// (validateStoredRemoteKill / validateStoredRollback) failed Ed25519 signature
// verification against the static operator-trusted control keys. It is dropped
// from every leader read/enumeration path so it can neither MOVE nor SUPPRESS
// the served stream head. The distinct rotation event names a quarantine caused
// by a signer key that is no longer in the trusted set (legitimate-but-stale),
// because that case can silently remove emergency state across a restart and an
// operator must see it. Both classes are logged loudly; the matching path is the
// only thing that differs.
const (
	auditRollbackQuarantine          = "conductor_rollback_reconcile_quarantined_unverified"
	auditRemoteKillQuarantine        = "conductor_remote_kill_quarantined_unverified"
	auditRollbackQuarantineRotation  = "conductor_rollback_quarantined_rotated_key"
	auditRemoteKillQuarantineRotated = "conductor_remote_kill_quarantined_rotated_key"
)

// verifiedEmergencyStore is the signature-verifying view of an EmergencyStore.
// It is the ONLY enumerator type the Handler is given: NewHandler wraps the
// configured store in this view, and the raw FileEmergencyStore enumeration
// (rollbackAuthorizations / remoteKills) is unexported so no future caller can
// reach the unfiltered records by accident. Every leader read path
// (LatestRemoteKill, LatestRollbackAuthorization, ActiveRollbackForFollower) and
// every enumeration path (RollbackAuthorizations, RemoteKills used by startup
// reconcile and stream-status) goes through here, so a forged record that only
// passed structural validation at load is filtered out before it can influence
// the served head.
//
// Defense-in-depth: signature verification is the real gate that already runs at
// publish ingress (handlePublish*). This view re-applies it at READ time so a
// record planted directly on disk (a LOCAL precondition, not a remote bypass)
// cannot move or suppress served state. A nil/empty resolver quarantines ALL
// records (fail closed) but does NOT crash startup.
type verifiedEmergencyStore struct {
	inner   EmergencyStore
	resolve conductor.SignatureKeyResolver
	logger  *slog.Logger
	metrics quarantineCounter
	// enumRoll / enumKills read the UNFILTERED stored records from the inner
	// store. They are nil when the inner store does not support enumeration, in
	// which case the verified view reports no records (degrades to "no active
	// controls", exactly as an enumeration-less store did before).
	enumRoll  func(context.Context) ([]StoredRollbackAuthorization, error)
	enumKills func(context.Context) ([]StoredRemoteKill, error)
}

// quarantineCounter records a quarantine for observability. *metrics.Metrics
// satisfies it; nil is tolerated.
type quarantineCounter interface {
	RecordConductorEmergencyQuarantine(control, reason string)
}

// rawRollbackEnumerator / rawRemoteKillEnumerator are the UNEXPORTED enumeration
// surfaces the production store ([FileEmergencyStore]) exposes. Unexported
// method names mean a caller OUTSIDE this package cannot obtain the unfiltered
// records; only the in-package verified view consumes them, and it filters
// every record through signature verification first.
type rawRollbackEnumerator interface {
	enumerateRollbacks(context.Context) ([]StoredRollbackAuthorization, error)
}

type rawRemoteKillEnumerator interface {
	enumerateRemoteKills(context.Context) ([]StoredRemoteKill, error)
}

// newVerifiedEmergencyStore wraps an EmergencyStore in the signature-verifying
// view. inner==nil yields nil (the Handler treats a nil store as "no emergency
// controls configured", same as before). resolve may be nil/empty; in that case
// every record quarantines (fail closed) but startup does not crash.
//
// The view binds the inner store's unfiltered enumeration via the UNEXPORTED
// raw interface (the production [FileEmergencyStore] path) and falls back to the
// EXPORTED enumerator interface for alternate/in-package stores (e.g. test
// doubles). Either way, the records flow through verifyRollback/verifyRemoteKill
// before any caller sees them — the Handler never holds a path to the unfiltered
// records.
func newVerifiedEmergencyStore(inner EmergencyStore, resolve conductor.SignatureKeyResolver, logger *slog.Logger, m quarantineCounter) EmergencyStore {
	if inner == nil {
		return nil
	}
	v := &verifiedEmergencyStore{
		inner:   inner,
		resolve: resolve,
		logger:  logger,
		metrics: m,
	}
	switch r := inner.(type) {
	case rawRollbackEnumerator:
		v.enumRoll = r.enumerateRollbacks
	case rollbackAuthorizationEnumerator:
		v.enumRoll = r.RollbackAuthorizations
	}
	switch r := inner.(type) {
	case rawRemoteKillEnumerator:
		v.enumKills = r.enumerateRemoteKills
	case remoteKillEnumerator:
		v.enumKills = r.RemoteKills
	}
	return v
}

// verifyRollback reports whether a stored rollback authorization is signature-
// verified against the trusted control keys at now. A failure is quarantined
// (dropped) and logged loudly; the rotation flavor is used when the signer is a
// known-shape key that is simply no longer trusted (resolver miss), which an
// operator must notice because it can silently remove emergency state.
func (v *verifiedEmergencyStore) verifyRollback(record StoredRollbackAuthorization, now time.Time) bool {
	if v.resolve == nil {
		v.quarantineRollback(record, "nil_resolver", auditRollbackQuarantine)
		return false
	}
	if err := record.Authorization.VerifySignaturesAt(now, v.resolve); err != nil {
		event, reason := v.classifyQuarantine(record.Authorization.Signatures, auditRollbackQuarantine, auditRollbackQuarantineRotation)
		v.quarantineRollback(record, reason, event)
		return false
	}
	return true
}

// verifyRemoteKill mirrors verifyRollback for remote-kill messages.
func (v *verifiedEmergencyStore) verifyRemoteKill(record StoredRemoteKill, now time.Time) bool {
	if v.resolve == nil {
		v.quarantineRemoteKill(record, "nil_resolver", auditRemoteKillQuarantine)
		return false
	}
	if err := record.Message.VerifySignaturesAt(now, v.resolve); err != nil {
		event, reason := v.classifyQuarantine(record.Message.Signatures, auditRemoteKillQuarantine, auditRemoteKillQuarantineRotated)
		v.quarantineRemoteKill(record, reason, event)
		return false
	}
	return true
}

func (v *verifiedEmergencyStore) quarantineRollback(record StoredRollbackAuthorization, reason, event string) {
	if v.logger != nil {
		v.logger.Error(event,
			"authorization_id", record.Authorization.AuthorizationID,
			"authorization_hash", record.AuthorizationHash,
			"org_id", record.Authorization.OrgID,
			"fleet_id", record.Authorization.FleetID,
			"counter", record.Authorization.Counter,
			"reason", reason,
		)
	}
	if v.metrics != nil {
		v.metrics.RecordConductorEmergencyQuarantine("rollback", reason)
	}
}

func (v *verifiedEmergencyStore) quarantineRemoteKill(record StoredRemoteKill, reason, event string) {
	if v.logger != nil {
		v.logger.Error(event,
			"message_id", record.Message.MessageID,
			"message_hash", record.MessageHash,
			"org_id", record.Message.OrgID,
			"fleet_id", record.Message.FleetID,
			"counter", record.Message.Counter,
			"reason", reason,
		)
	}
	if v.metrics != nil {
		v.metrics.RecordConductorEmergencyQuarantine("remote_kill", reason)
	}
}

// EmergencyStore interface: each read path filters its candidates through
// signature verification BEFORE the underlying newest-wins selection. The
// verified view re-implements the selection over the verified subset rather than
// delegating to inner's Latest*/Active* (which select over the UNVERIFIED set),
// because a forged HIGH-counter record could otherwise win newest-wins inside
// inner and either move the head or, via counter dominance, suppress a legit
// lower-counter control.

func (v *verifiedEmergencyStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	// Publish is a write path; signature verification already happens at the
	// handler ingress before this is reached. Delegate unchanged.
	return v.inner.PublishRemoteKill(ctx, msg, now)
}

func (v *verifiedEmergencyStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return v.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (v *verifiedEmergencyStore) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	if err := follower.Validate(); err != nil {
		return StoredRemoteKill{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	records, err := v.verifiedRemoteKills(ctx, now)
	if err != nil {
		return StoredRemoteKill{}, err
	}
	var best StoredRemoteKill
	for _, record := range records {
		if err := record.Message.ValidateAtTime(now); err != nil {
			continue
		}
		if err := record.Message.ValidateForFollower(follower.OrgID, follower.FleetID, follower.InstanceID, follower.Labels); err != nil {
			continue
		}
		if best.MessageHash == "" || newerRemoteKill(record, best) {
			best = record
		}
	}
	if best.MessageHash == "" {
		return StoredRemoteKill{}, ErrEmergencyNotFound
	}
	return best, nil
}

func (v *verifiedEmergencyStore) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	if err := follower.Validate(); err != nil {
		return StoredRollbackAuthorization{}, err
	}
	if err := lookup.Validate(); err != nil {
		return StoredRollbackAuthorization{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	records, err := v.verifiedRollbacks(ctx, now)
	if err != nil {
		return StoredRollbackAuthorization{}, err
	}
	var best StoredRollbackAuthorization
	for _, record := range records {
		auth := record.Authorization
		if auth.CurrentBundleID != lookup.CurrentBundleID ||
			auth.CurrentVersion != lookup.CurrentVersion ||
			auth.TargetBundleID != lookup.TargetBundleID ||
			auth.TargetVersion != lookup.TargetVersion {
			continue
		}
		if err := auth.ValidateAtTime(now); err != nil {
			continue
		}
		if auth.OrgID != follower.OrgID || auth.FleetID != follower.FleetID {
			continue
		}
		if best.AuthorizationHash == "" || newerRollback(record, best) {
			best = record
		}
	}
	if best.AuthorizationHash == "" {
		return StoredRollbackAuthorization{}, ErrEmergencyNotFound
	}
	return best, nil
}

func (v *verifiedEmergencyStore) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	if err := follower.Validate(); err != nil {
		return StoredRollbackAuthorization{}, false, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	records, err := v.verifiedRollbacks(ctx, now)
	if err != nil {
		return StoredRollbackAuthorization{}, false, err
	}
	var best StoredRollbackAuthorization
	for _, record := range records {
		auth := record.Authorization
		if err := auth.ValidateAtTime(now); err != nil {
			continue
		}
		if auth.OrgID != follower.OrgID || auth.FleetID != follower.FleetID {
			continue
		}
		if best.AuthorizationHash == "" || newerRollback(record, best) {
			best = record
		}
	}
	if best.AuthorizationHash == "" {
		return StoredRollbackAuthorization{}, false, nil
	}
	return best, true, nil
}

// verifiedRollbacks returns the signature-verified subset of stored rollback
// authorizations. Unverified records are quarantined (dropped + logged) here, so
// they never reach any selection logic.
func (v *verifiedEmergencyStore) verifiedRollbacks(ctx context.Context, now time.Time) ([]StoredRollbackAuthorization, error) {
	if v.enumRoll == nil {
		return nil, nil
	}
	records, err := v.enumRoll(ctx)
	if err != nil {
		return nil, err
	}
	verified := make([]StoredRollbackAuthorization, 0, len(records))
	for _, record := range records {
		if v.verifyRollback(record, now) {
			verified = append(verified, record)
		}
	}
	return verified, nil
}

// verifiedRemoteKills mirrors verifiedRollbacks for remote-kill messages.
func (v *verifiedEmergencyStore) verifiedRemoteKills(ctx context.Context, now time.Time) ([]StoredRemoteKill, error) {
	if v.enumKills == nil {
		return nil, nil
	}
	records, err := v.enumKills(ctx)
	if err != nil {
		return nil, err
	}
	verified := make([]StoredRemoteKill, 0, len(records))
	for _, record := range records {
		if v.verifyRemoteKill(record, now) {
			verified = append(verified, record)
		}
	}
	return verified, nil
}

// RollbackAuthorizations satisfies rollbackAuthorizationEnumerator. It returns
// ONLY signature-verified records, so startup reconcile (reconcileRollbackHeads)
// and stream-status enumeration both operate on the verified subset. The
// verification time is now() so a key that has expired/been revoked at read time
// quarantines.
//
// Using time.Now() here (rather than threading a caller-supplied instant) is
// intentional: these enumerator entry points feed advisory paths (startup
// reconcile, read-only stream-status display), and "is this signer trusted
// right now" is the correct question for them. The Latest*/Active* paths, which
// drive the served decision, verify and validity-check at the SAME caller now,
// so there is no exploitable valid-at-A-selected-at-B gap on the decision path.
func (v *verifiedEmergencyStore) RollbackAuthorizations(ctx context.Context) ([]StoredRollbackAuthorization, error) {
	return v.verifiedRollbacks(ctx, time.Now().UTC())
}

// RemoteKills satisfies remoteKillEnumerator with the verified subset.
func (v *verifiedEmergencyStore) RemoteKills(ctx context.Context) ([]StoredRemoteKill, error) {
	return v.verifiedRemoteKills(ctx, time.Now().UTC())
}

// ClearRollbackAuthorization forwards an admin clear to the underlying store if
// it supports clearing. The verified view does not gate clears: removing a
// record (verified or not) only ever shrinks served state, so it is safe to
// pass through, and an operator must be able to clear a quarantined-but-present
// record from disk.
func (v *verifiedEmergencyStore) ClearRollbackAuthorization(ctx context.Context, authorizationID string) (bool, error) {
	clearer, ok := v.inner.(rollbackClearer)
	if !ok {
		return false, ErrEmergencyClearUnsupported
	}
	return clearer.ClearRollbackAuthorization(ctx, authorizationID)
}

// PreviewRemoteKill forwards a remote-kill dry-run preview to the underlying
// store if it supports previewing. Signature verification already happens at the
// handler ingress before the preview is reached (same as PublishRemoteKill), so
// the pass-through is verification-parity-safe. A store that cannot preview fails
// closed with ErrEmergencyPreviewUnsupported rather than pretending a dry-run
// succeeded.
func (v *verifiedEmergencyStore) PreviewRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (RemoteKillPreview, error) {
	previewer, ok := v.inner.(remoteKillPreviewer)
	if !ok {
		return RemoteKillPreview{}, ErrEmergencyPreviewUnsupported
	}
	return previewer.PreviewRemoteKill(ctx, msg, now)
}

// PreviewRollbackAuthorization mirrors PreviewRemoteKill for rollback
// authorizations.
func (v *verifiedEmergencyStore) PreviewRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (RollbackAuthPreview, error) {
	previewer, ok := v.inner.(rollbackAuthPreviewer)
	if !ok {
		return RollbackAuthPreview{}, ErrEmergencyPreviewUnsupported
	}
	return previewer.PreviewRollbackAuthorization(ctx, auth, now)
}

// classifyQuarantine picks the audit event + reason for a verification failure.
// A resolver MISS (a signer key id not in the trusted set) is the key-rotation
// case: the record may be legitimate but signed by a rotated-out key, which can
// silently remove emergency state on restart, so it gets the distinct rotation
// event name and an operator must notice it. Any other verification failure (bad
// signature bytes, wrong purpose, expired/revoked key, threshold) is a
// forged/invalid record and gets the base quarantine event.
//
// Classification probes the resolver directly rather than parsing the error
// string: both a resolver miss and a bad-signature wrap the same
// [conductor.ErrSignatureVerification] sentinel, so the error alone cannot
// distinguish them. A nil resolver is handled by the callers before reaching
// here. If any signer id fails to resolve, treat it as the rotation case.
//
// This labeling is observability-only and best-effort: it never affects the
// drop decision (the record is already being quarantined). A mixed record
// (one trusted-but-bad-signature signer plus one unknown signer id) is
// conservatively labeled rotation, which is the safer triage signal — it
// prompts the operator to check for a key they rotated out rather than
// silently treating a partly-forged record as routine.
func (v *verifiedEmergencyStore) classifyQuarantine(signatures []conductor.SignatureProof, baseEvent, rotationEvent string) (event, reason string) {
	if v.resolve != nil {
		for _, sig := range signatures {
			if _, err := v.resolve(sig.SignerKeyID); err != nil {
				return rotationEvent, "untrusted_or_rotated_signer"
			}
		}
	}
	return baseEvent, "signature_verification_failed"
}
