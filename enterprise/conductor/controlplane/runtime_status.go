//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

const (
	FollowerRuntimeStatusPath = "/api/v1/conductor/follower/status"

	defaultRuntimeStatusStaleAfter  = 5 * time.Minute
	maxFollowerRuntimeStatusRecords = 10000
	maxRuntimeStatusStringBytes     = 256
	maxApplyErrorMessageRunes       = 512
)

var (
	ErrRuntimeStatusStoreRequired    = errors.New("conductor runtime status store required")
	ErrRuntimeStatusIdentityMismatch = errors.New("conductor runtime status identity mismatch")
	ErrRuntimeStatusLimitExceeded    = errors.New("conductor runtime status record limit exceeded")
	ErrFleetPreflightBlocked         = errors.New("conductor publish preflight blocked by fleet runtime skew")
)

type FleetHealth string

const (
	FleetHealthOK          FleetHealth = "ok"
	FleetHealthStale       FleetHealth = "stale"
	FleetHealthUnsupported FleetHealth = "unsupported"
	FleetHealthApplyFailed FleetHealth = "apply_failed"
	FleetHealthUnknown     FleetHealth = "unknown"
)

type FleetFieldSource string

const (
	FleetFieldSourceNone               FleetFieldSource = "none"
	FleetFieldSourceRuntimeStatus      FleetFieldSource = "runtime_status"
	FleetFieldSourceSignedAppliedState FleetFieldSource = "signed_applied_state"
)

type FollowerRuntimeStatus struct {
	OrgID                          string    `json:"org_id"`
	FleetID                        string    `json:"fleet_id"`
	InstanceID                     string    `json:"instance_id"`
	Environment                    string    `json:"environment"`
	PipelockVersion                string    `json:"pipelock_version"`
	GitCommit                      string    `json:"git_commit"`
	BuildDate                      string    `json:"build_date"`
	SchemaVersion                  int       `json:"schema_version"`
	ActiveBundleID                 string    `json:"active_bundle_id"`
	ActiveBundleVersion            uint64    `json:"active_bundle_version"`
	ActiveBundleHash               string    `json:"active_bundle_hash"`
	ActiveBundleMinPipelockVersion string    `json:"active_bundle_min_pipelock_version"`
	LastPolicyPollAt               time.Time `json:"last_policy_poll_at"`
	LastSuccessfulApplyAt          time.Time `json:"last_successful_apply_at,omitempty"`
	LastApplyErrorCode             string    `json:"last_apply_error_code,omitempty"`
	LastApplyErrorMessage          string    `json:"last_apply_error_message,omitempty"`
	LastSeenAt                     time.Time `json:"last_seen_at"`
}

type RuntimeStatusQuery struct {
	OrgID      string
	FleetID    string
	InstanceID string
	Limit      int
}

type RuntimeStatusStore interface {
	UpsertFollowerRuntimeStatus(context.Context, FollowerRuntimeStatus) (FollowerRuntimeStatus, error)
	ListFollowerRuntimeStatus(context.Context, RuntimeStatusQuery) ([]FollowerRuntimeStatus, error)
}

type RuntimePreflightEnrollmentStore interface {
	ListEnrolledFollowersForPreflight(context.Context, FollowerListQuery) ([]FollowerSummary, bool, error)
}

type ExpectedBundle struct {
	BundleID                  string `json:"bundle_id,omitempty"`
	Version                   uint64 `json:"version,omitempty"`
	BundleHash                string `json:"bundle_hash,omitempty"`
	MinPipelockVersion        string `json:"min_pipelock_version,omitempty"`
	AudienceLabelsUnavailable bool   `json:"audience_labels_unavailable,omitempty"`
}

type FollowerFleetStatus struct {
	FollowerSummary
	RuntimeStatus *FollowerRuntimeStatus `json:"runtime_status,omitempty"`
	// SignedAppliedState is the cryptographically verified applied-state from the
	// follower's signed audit-batch path, when available. It is the trustworthy
	// source of what the follower is running; RuntimeStatus (the unsigned POST)
	// remains for followers that predate signed applied-state. Consumers should
	// prefer SignedAppliedState when present.
	SignedAppliedState *VerifiedAppliedState `json:"signed_applied_state,omitempty"`
	Health             FleetHealth           `json:"health"`
	HealthSource       FleetFieldProvenance  `json:"health_source"`
	Drift              string                `json:"drift,omitempty"`
	DriftSource        *FleetFieldProvenance `json:"drift_source,omitempty"`
	ExpectedBundle     ExpectedBundle        `json:"expected_bundle,omitempty"`
}

type FleetFieldProvenance struct {
	Source       FleetFieldSource `json:"source"`
	Verified     bool             `json:"verified"`
	ObservedAt   *time.Time       `json:"observed_at,omitempty"`
	VerifiedAt   *time.Time       `json:"verified_at,omitempty"`
	ProvenanceAt *time.Time       `json:"provenance_at,omitempty"`
}

type PublishPreflightSummary struct {
	CanApply          int    `json:"can_apply"`
	Unsupported       int    `json:"unsupported"`
	StaleUnseen       int    `json:"stale_unseen"`
	LastApplyFailed   int    `json:"last_apply_failed"`
	OutOfAudience     int    `json:"out_of_audience"`
	ActiveInScope     int    `json:"active_in_scope"`
	AllowFleetSkew    bool   `json:"allow_fleet_skew"`
	FleetSkewReason   string `json:"fleet_skew_reason,omitempty"`
	StaleAfterSeconds int    `json:"stale_after_seconds"`
	Unavailable       bool   `json:"unavailable,omitempty"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

func (s FollowerRuntimeStatus) Identity() FollowerIdentity {
	return FollowerIdentity{
		OrgID:       s.OrgID,
		FleetID:     s.FleetID,
		InstanceID:  s.InstanceID,
		Environment: s.Environment,
	}
}

func sameFollowerIdentity(a, b FollowerIdentity) bool {
	return a.OrgID == b.OrgID &&
		a.FleetID == b.FleetID &&
		a.InstanceID == b.InstanceID &&
		a.Environment == b.Environment
}

func normalizeRuntimeStatus(in FollowerRuntimeStatus, now time.Time) (FollowerRuntimeStatus, error) {
	identity := in.Identity()
	if err := identity.Validate(); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	out := in
	out.OrgID = identity.OrgID
	out.FleetID = identity.FleetID
	out.InstanceID = identity.InstanceID
	out.Environment = identity.Environment
	var err error
	if out.PipelockVersion, err = boundedRuntimeString("pipelock_version", out.PipelockVersion); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.GitCommit, err = boundedRuntimeString("git_commit", out.GitCommit); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.BuildDate, err = boundedRuntimeString("build_date", out.BuildDate); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.ActiveBundleID, err = boundedRuntimeString("active_bundle_id", out.ActiveBundleID); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.ActiveBundleHash, err = boundedRuntimeString("active_bundle_hash", out.ActiveBundleHash); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	out.ActiveBundleHash = strings.ToLower(out.ActiveBundleHash)
	if out.ActiveBundleMinPipelockVersion, err = boundedRuntimeString("active_bundle_min_pipelock_version", out.ActiveBundleMinPipelockVersion); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.LastApplyErrorCode, err = boundedRuntimeString("last_apply_error_code", out.LastApplyErrorCode); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.LastApplyErrorMessage, err = sanitizeApplyErrorMessage(out.LastApplyErrorMessage); err != nil {
		return FollowerRuntimeStatus{}, err
	}
	if out.SchemaVersion == 0 {
		out.SchemaVersion = conductor.SchemaVersion
	}
	if out.ActiveBundleHash != "" {
		if err := validateRuntimeHash(out.ActiveBundleHash); err != nil {
			return FollowerRuntimeStatus{}, err
		}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	out.LastSeenAt = now
	out.LastPolicyPollAt = normalizeTime(out.LastPolicyPollAt)
	out.LastSuccessfulApplyAt = normalizeTime(out.LastSuccessfulApplyAt)
	return out, nil
}

func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

func boundedRuntimeString(field string, s string) (string, error) {
	s = strings.TrimSpace(sanitizeControlString(s))
	if len(s) <= maxRuntimeStatusStringBytes {
		return s, nil
	}
	return "", fmt.Errorf("%w: %s (%d bytes > cap %d)", conductor.ErrPayloadTooLarge, field, len(s), maxRuntimeStatusStringBytes)
}

func sanitizeApplyErrorMessage(s string) (string, error) {
	s = strings.TrimSpace(sanitizeControlString(s))
	runes := []rune(s)
	if len(runes) > maxApplyErrorMessageRunes {
		return "", fmt.Errorf("%w: last_apply_error_message (%d runes > cap %d)", conductor.ErrPayloadTooLarge, len(runes), maxApplyErrorMessageRunes)
	}
	return s, nil
}

func sanitizeControlString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || !unicode.IsPrint(r) {
			r = ' '
		}
		if r == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

func validateRuntimeHash(hash string) error {
	if len(hash) != 64 {
		return fmt.Errorf("%w: active_bundle_hash", conductor.ErrInvalidHash)
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("%w: active_bundle_hash", conductor.ErrInvalidHash)
		}
	}
	return nil
}

func runtimeStatusMap(statuses []FollowerRuntimeStatus) map[string]FollowerRuntimeStatus {
	out := make(map[string]FollowerRuntimeStatus, len(statuses))
	for _, status := range statuses {
		out[followerEnrollmentKey(status.Identity())] = status
	}
	return out
}

func expectedBundleForFollower(streams []StreamSummary, follower FollowerSummary, now time.Time) ExpectedBundle {
	identity := FollowerIdentity{
		OrgID:       follower.OrgID,
		FleetID:     follower.FleetID,
		InstanceID:  follower.InstanceID,
		Environment: follower.Environment,
	}
	var best StreamSummary
	bestSpecificity := 0
	labelsUnavailable := false
	for _, stream := range streams {
		if stream.OrgID != follower.OrgID || stream.FleetID != follower.FleetID || stream.Environment != follower.Environment {
			continue
		}
		if stream.HeadBundleHash != "" && len(stream.Audience.Labels) > 0 {
			labelsUnavailable = true
		}
		specificity := streamSpecificity(stream, identity, now)
		if specificity > 0 && (best.HeadBundleHash == "" || specificity > bestSpecificity || (specificity == bestSpecificity && stream.HeadVersion > best.HeadVersion)) {
			best = stream
			bestSpecificity = specificity
		}
	}
	if labelsUnavailable && bestSpecificity < 3 {
		return ExpectedBundle{AudienceLabelsUnavailable: true}
	}
	if best.HeadBundleHash == "" {
		return ExpectedBundle{}
	}
	return ExpectedBundle{
		BundleID:           best.HeadBundleID,
		Version:            best.HeadVersion,
		BundleHash:         best.HeadBundleHash,
		MinPipelockVersion: bestHeadMinPipelockVersion(best),
	}
}

func streamSpecificity(stream StreamSummary, identity FollowerIdentity, _ time.Time) int {
	if slices.Contains(stream.Audience.InstanceIDs, identity.InstanceID) {
		return 3
	}
	if len(stream.Audience.Labels) > 0 && stream.Audience.Matches(identity.InstanceID, identity.Labels) {
		return 2
	}
	if slices.Contains(stream.Audience.InstanceIDs, "*") {
		return 1
	}
	return 0
}

func bestHeadMinPipelockVersion(stream StreamSummary) string {
	for _, entry := range stream.BundleChain {
		if entry.BundleHash == stream.HeadBundleHash {
			return entry.MinPipelockVersion
		}
	}
	return ""
}

func classifyFollowerHealth(follower FollowerSummary, status *FollowerRuntimeStatus, expected ExpectedBundle, now time.Time, staleAfter time.Duration) (FleetHealth, string) {
	if status == nil {
		return FleetHealthUnknown, "no_status"
	}
	if staleAfter <= 0 {
		staleAfter = defaultRuntimeStatusStaleAfter
	}
	if status.LastSeenAt.IsZero() || now.Sub(status.LastSeenAt) > staleAfter {
		return FleetHealthStale, "status_stale"
	}
	if status.LastApplyErrorCode != "" || status.LastApplyErrorMessage != "" {
		return FleetHealthApplyFailed, "last_apply_failed"
	}
	if expected.AudienceLabelsUnavailable {
		return FleetHealthUnknown, "audience_labels_unavailable"
	}
	minVersion := expected.MinPipelockVersion
	if minVersion == "" {
		minVersion = status.ActiveBundleMinPipelockVersion
	}
	if minVersion != "" && rules.CheckMinPipelock(minVersion, status.PipelockVersion) != nil {
		return FleetHealthUnsupported, "runtime_below_minimum"
	}
	if expected.BundleHash != "" && !strings.EqualFold(status.ActiveBundleHash, expected.BundleHash) {
		return FleetHealthStale, "bundle_mismatch"
	}
	if !follower.Active {
		return FleetHealthStale, "inactive_enrollment"
	}
	return FleetHealthOK, ""
}

func classifyFollowerFleetStatus(
	follower FollowerSummary,
	status *FollowerRuntimeStatus,
	signed *VerifiedAppliedState,
	expected ExpectedBundle,
	now time.Time,
	staleAfter time.Duration,
) (FleetHealth, string, FleetFieldProvenance) {
	if signed != nil && signed.Verified {
		health, drift := classifySignedAppliedState(follower, *signed, expected, now, staleAfter)
		return health, drift, signedAppliedStateProvenance(*signed)
	}
	health, drift := classifyFollowerHealth(follower, status, expected, now, staleAfter)
	return health, drift, runtimeStatusProvenance(status)
}

func classifySignedAppliedState(follower FollowerSummary, signed VerifiedAppliedState, expected ExpectedBundle, now time.Time, staleAfter time.Duration) (FleetHealth, string) {
	if staleAfter <= 0 {
		staleAfter = defaultRuntimeStatusStaleAfter
	}
	applied := signed.AppliedState
	// The signed state must be fresh by BOTH the server's receipt time AND the
	// follower's own provenance time. Relying on VerifiedAt alone lets a stale
	// applied-state resubmitted in a fresh audit batch look current and mask
	// drift. ProvenanceAt is the follower's freshness stamp; fall back to
	// ObservedAt for legacy clients. Reject zero, too-old, and too-far-future.
	if signed.VerifiedAt.IsZero() || now.Sub(signed.VerifiedAt) > staleAfter || signed.VerifiedAt.After(now.Add(staleAfter)) {
		return FleetHealthStale, "signed_state_stale"
	}
	provenance := applied.ProvenanceAt
	if provenance.IsZero() {
		provenance = applied.ObservedAt
	}
	if provenance.IsZero() || now.Sub(provenance) > staleAfter || provenance.After(now.Add(staleAfter)) {
		return FleetHealthStale, "signed_state_stale"
	}
	if applied.LastApplyErrorCode != "" || applied.LastApplyErrorMessage != "" {
		return FleetHealthApplyFailed, "last_apply_failed"
	}
	if expected.AudienceLabelsUnavailable {
		return FleetHealthUnknown, "audience_labels_unavailable"
	}
	minVersion := expected.MinPipelockVersion
	if minVersion == "" {
		minVersion = applied.ActiveBundleMinPipelockVersion
	}
	if minVersion != "" && rules.CheckMinPipelock(minVersion, applied.PipelockVersion) != nil {
		return FleetHealthUnsupported, "runtime_below_minimum"
	}
	if expected.BundleHash != "" && !strings.EqualFold(applied.ActiveBundleHash, expected.BundleHash) {
		return FleetHealthStale, "bundle_mismatch"
	}
	if !follower.Active {
		return FleetHealthStale, "inactive_enrollment"
	}
	return FleetHealthOK, ""
}

func runtimeStatusProvenance(status *FollowerRuntimeStatus) FleetFieldProvenance {
	p := FleetFieldProvenance{Source: FleetFieldSourceNone}
	if status == nil {
		return p
	}
	p.Source = FleetFieldSourceRuntimeStatus
	p.ObservedAt = utcTimePtr(status.LastSeenAt)
	return p
}

func signedAppliedStateProvenance(signed VerifiedAppliedState) FleetFieldProvenance {
	return FleetFieldProvenance{
		Source:       FleetFieldSourceSignedAppliedState,
		Verified:     true,
		ObservedAt:   utcTimePtr(signed.ObservedAt),
		VerifiedAt:   utcTimePtr(signed.VerifiedAt),
		ProvenanceAt: utcTimePtr(signed.AppliedState.ProvenanceAt),
	}
}

func utcTimePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	utc := t.UTC()
	return &utc
}

func preflightAudienceMatches(audience conductor.Audience, follower FollowerSummary) bool {
	if len(audience.Labels) > 0 {
		return false
	}
	return audience.Matches(follower.InstanceID, nil)
}

type publishPreflightOptions struct {
	now             time.Time
	staleAfter      time.Duration
	allowFleetSkew  bool
	fleetSkewReason string
}

func evaluatePublishPreflight(followers []FollowerSummary, statuses []FollowerRuntimeStatus, bundle conductor.PolicyBundle, opts publishPreflightOptions) (PublishPreflightSummary, error) {
	staleAfter := opts.staleAfter
	if staleAfter <= 0 {
		staleAfter = defaultRuntimeStatusStaleAfter
	}
	statusByID := runtimeStatusMap(statuses)
	summary := PublishPreflightSummary{
		AllowFleetSkew:    opts.allowFleetSkew,
		FleetSkewReason:   opts.fleetSkewReason,
		StaleAfterSeconds: int(staleAfter / time.Second),
	}
	if len(bundle.Audience.Labels) > 0 {
		return summary, fmt.Errorf("%w: label-scoped audience cannot be evaluated without follower labels", ErrFleetPreflightBlocked)
	}
	for _, follower := range followers {
		if !follower.Active {
			continue
		}
		if follower.OrgID != bundle.OrgID || follower.FleetID != bundle.FleetID || follower.Environment != bundle.Environment {
			summary.OutOfAudience++
			continue
		}
		if !preflightAudienceMatches(bundle.Audience, follower) {
			summary.OutOfAudience++
			continue
		}
		summary.ActiveInScope++
		status, ok := statusByID[followerEnrollmentKey(FollowerIdentity{
			OrgID:       follower.OrgID,
			FleetID:     follower.FleetID,
			InstanceID:  follower.InstanceID,
			Environment: follower.Environment,
		})]
		if !ok || status.LastSeenAt.IsZero() || opts.now.Sub(status.LastSeenAt) > staleAfter {
			summary.StaleUnseen++
			continue
		}
		if status.LastApplyErrorCode != "" || status.LastApplyErrorMessage != "" {
			summary.LastApplyFailed++
			continue
		}
		if err := rules.CheckMinPipelock(bundle.MinPipelockVersion, status.PipelockVersion); err != nil {
			summary.Unsupported++
			continue
		}
		summary.CanApply++
	}
	if !opts.allowFleetSkew && (summary.Unsupported > 0 || summary.StaleUnseen > 0 || summary.LastApplyFailed > 0) {
		return summary, fmt.Errorf("%w: unsupported=%d stale_unseen=%d last_apply_failed=%d", ErrFleetPreflightBlocked, summary.Unsupported, summary.StaleUnseen, summary.LastApplyFailed)
	}
	return summary, nil
}
