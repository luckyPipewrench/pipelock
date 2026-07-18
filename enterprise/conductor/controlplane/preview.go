//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

var (
	// ErrDryRunUnsupported is returned when a dry-run is requested against a
	// BundleStore that does not implement the read-only preview surface. It fails
	// closed: a dry-run that cannot be evaluated must not report "would succeed".
	ErrDryRunUnsupported = errors.New("conductor bundle store does not support dry-run preview")
	// ErrEmergencyPreviewUnsupported is the emergency-store counterpart of
	// ErrDryRunUnsupported.
	ErrEmergencyPreviewUnsupported = errors.New("conductor emergency store does not support dry-run preview")
	// ErrRollbackHeadPreviewUnsupported is returned when live rollback cannot
	// preflight the head mutation needed to avoid split-write orphan state.
	ErrRollbackHeadPreviewUnsupported = errors.New("conductor bundle store does not support rollback head preview")
)

// Preview types are the read-only projections a dry-run reports. Each Preview*
// method below runs the exact same shared decision core its mutating sibling
// runs (buildPublishRecord/publishDecisionLocked, rollbackHeadDecisionLocked,
// remoteKillDecisionLocked, rollbackAuthDecisionLocked) under a READ lock and
// performs no writes, so a dry-run's verdict can never diverge from the real
// apply on identical inputs and state.

// PublishPreview reports what a policy-bundle publish would do without writing.
// WouldCreate is true when a new record would be written and false when the
// publish is an idempotent re-publish of an already-stored identical bundle.
type PublishPreview struct {
	WouldCreate        bool
	ResultHash         string
	ResultVersion      uint64
	HasCurrentHead     bool
	CurrentHeadVersion uint64
	CurrentHeadHash    string
}

// RollbackHeadPreview reports what applying a rollback authorization would do to
// the effective stream head without writing. Noop is true when a later forward
// publish already supersedes the rollback so the head would not move.
type RollbackHeadPreview struct {
	WouldRollToBundleID string
	WouldRollToVersion  uint64
	WouldRollToHash     string
	Noop                bool
	CurrentHeadVersion  uint64
	CurrentHeadHash     string
}

// RemoteKillPreview reports what publishing a remote-kill message would do
// without writing. WouldCreate is false for an idempotent re-publish.
type RemoteKillPreview struct {
	WouldCreate          bool
	MessageHash          string
	Counter              uint64
	HasCurrentMaxCounter bool
	CurrentMaxCounter    uint64
}

// RollbackAuthPreview reports what publishing a rollback authorization would do
// to the emergency store without writing. WouldCreate is false for an idempotent
// re-publish.
type RollbackAuthPreview struct {
	WouldCreate          bool
	AuthorizationHash    string
	Counter              uint64
	HasCurrentMaxCounter bool
	CurrentMaxCounter    uint64
}

// publishPreviewer is the optional interface a BundleStore implements to support
// publish dry-run. Mirrors the codebase's optional-interface pattern
// (rollbackClearer, RuntimeStatusStore) so the mutating BundleStore interface is
// unchanged and non-previewing stores fail closed rather than silently allowing.
type publishPreviewer interface {
	PreviewPublish(context.Context, conductor.PolicyBundle, PublishOptions) (PublishPreview, error)
}

type rollbackHeadPreviewer interface {
	PreviewRollbackHead(context.Context, conductor.RollbackAuthorization) (RollbackHeadPreview, error)
}

type remoteKillPreviewer interface {
	PreviewRemoteKill(context.Context, conductor.RemoteKillMessage, time.Time) (RemoteKillPreview, error)
}

type rollbackAuthPreviewer interface {
	PreviewRollbackAuthorization(context.Context, conductor.RollbackAuthorization, time.Time) (RollbackAuthPreview, error)
}

// PreviewPublish evaluates a policy-bundle publish without mutating the store. It
// shares buildPublishRecord + publishDecisionLocked with Publish, so it returns
// the identical validation/conflict error a real publish would (mapped by the
// handler via publishConflictCode) and no write occurs.
func (s *FileBundleStore) PreviewPublish(_ context.Context, bundle conductor.PolicyBundle, opts PublishOptions) (PublishPreview, error) {
	if s == nil {
		return PublishPreview{}, ErrStoreRequired
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if opts.Rollback {
		return PublishPreview{}, ErrUnsupportedRollback
	}
	record, err := buildPublishRecord(bundle, now)
	if err != nil {
		return PublishPreview{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, idempotent, err := s.publishDecisionLocked(record)
	if err != nil {
		return PublishPreview{}, err
	}
	preview := PublishPreview{
		WouldCreate:   !idempotent,
		ResultHash:    record.BundleHash,
		ResultVersion: record.Bundle.Version,
	}
	if idempotent {
		preview.ResultHash = existing.BundleHash
		preview.ResultVersion = existing.Bundle.Version
	}
	if head, ok := s.streams[record.StreamKey]; ok {
		preview.HasCurrentHead = true
		preview.CurrentHeadVersion = head.Bundle.Version
		preview.CurrentHeadHash = head.BundleHash
	}
	return preview, nil
}

// PreviewRollbackHead evaluates applying a rollback authorization to the stream
// head without mutating the store. It shares rollbackHeadDecisionLocked with
// ApplyRollbackHead, so a dry-run's "would roll to" verdict matches the real
// apply and no marker is written.
func (s *FileBundleStore) PreviewRollbackHead(_ context.Context, auth conductor.RollbackAuthorization) (RollbackHeadPreview, error) {
	if s == nil {
		return RollbackHeadPreview{}, ErrStoreRequired
	}
	if err := auth.Validate(); err != nil {
		return RollbackHeadPreview{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	target, action, err := s.rollbackHeadDecisionLocked(auth)
	if err != nil {
		return RollbackHeadPreview{}, err
	}
	preview := RollbackHeadPreview{
		WouldRollToBundleID: target.Bundle.BundleID,
		WouldRollToVersion:  target.Bundle.Version,
		WouldRollToHash:     target.BundleHash,
		Noop:                action == rollbackHeadNoop,
	}
	if head, ok := s.streams[target.StreamKey]; ok {
		preview.CurrentHeadVersion = head.Bundle.Version
		preview.CurrentHeadHash = head.BundleHash
	}
	return preview, nil
}

// PreviewRemoteKill evaluates publishing a remote-kill message without mutating
// the emergency store. It shares remoteKillDecisionLocked with PublishRemoteKill.
func (s *FileEmergencyStore) PreviewRemoteKill(_ context.Context, msg conductor.RemoteKillMessage, now time.Time) (RemoteKillPreview, error) {
	if s == nil {
		return RemoteKillPreview{}, ErrEmergencyStoreRequired
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if err := msg.ValidateAtTime(now); err != nil {
		return RemoteKillPreview{}, err
	}
	hash, err := msg.CanonicalHash()
	if err != nil {
		return RemoteKillPreview{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, idempotent, err := s.remoteKillDecisionLocked(msg, hash)
	if err != nil {
		return RemoteKillPreview{}, err
	}
	preview := RemoteKillPreview{
		WouldCreate: !idempotent,
		MessageHash: hash,
		Counter:     msg.Counter,
	}
	if idempotent {
		preview.MessageHash = existing.MessageHash
	}
	if maxCounter, ok := s.maxRemoteKillCounterForOrgFleetLocked(msg.OrgID, msg.FleetID); ok {
		preview.HasCurrentMaxCounter = true
		preview.CurrentMaxCounter = maxCounter
	}
	return preview, nil
}

// PreviewRollbackAuthorization evaluates publishing a rollback authorization to
// the emergency store without mutating it. It shares rollbackAuthDecisionLocked
// with PublishRollbackAuthorization.
func (s *FileEmergencyStore) PreviewRollbackAuthorization(_ context.Context, auth conductor.RollbackAuthorization, now time.Time) (RollbackAuthPreview, error) {
	if s == nil {
		return RollbackAuthPreview{}, ErrEmergencyStoreRequired
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if err := auth.ValidateAtTime(now); err != nil {
		return RollbackAuthPreview{}, err
	}
	hash, err := auth.CanonicalHash()
	if err != nil {
		return RollbackAuthPreview{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, idempotent, err := s.rollbackAuthDecisionLocked(auth, hash)
	if err != nil {
		return RollbackAuthPreview{}, err
	}
	preview := RollbackAuthPreview{
		WouldCreate:       !idempotent,
		AuthorizationHash: hash,
		Counter:           auth.Counter,
	}
	if idempotent {
		preview.AuthorizationHash = existing.AuthorizationHash
	}
	if maxCounter, ok := s.maxRollbackCounterForOrgFleetLocked(auth.OrgID, auth.FleetID); ok {
		preview.HasCurrentMaxCounter = true
		preview.CurrentMaxCounter = maxCounter
	}
	return preview, nil
}
