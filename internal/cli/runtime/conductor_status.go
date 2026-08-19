//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const conductorStatusResponseBytes = 64 * 1024

type conductorPolicyStatusReporter struct {
	client   policysync.HTTPDoer
	endpoint string
	cfg      config.Conductor
	cache    *applycache.Cache
	// markerPath is the follower's local enrollment marker, and identity is
	// resolved from it lazily rather than once at construction.
	//
	// The poller that owns this reporter is built early in server startup, while
	// auto-enrolment writes the marker much later in the same startup. Resolving
	// at construction therefore found no marker on the one run that enrols, and
	// the reporter stayed nil for that whole process: a freshly enrolled follower
	// reported no runtime status until someone restarted it, which left fleet
	// status blind and made every publish need the admin-only skew override.
	// Measured before this change: zero posts across 35 poll cycles and a
	// successful bundle apply, then one post immediately after a restart.
	//
	// Resolution stays fail-closed. No marker means no report, exactly as before,
	// so the follower can never publish status while it is not enrolled.
	markerPath string
	identity   atomic.Pointer[conductorEnrollmentMarker]
	// latest holds the most recent StatusEvent so the audit producer's
	// applied-state provider (invoked asynchronously off recorder-entry
	// observation) can read the same poll/apply outcome the unsigned status POST
	// reports, without coupling the producer to the poller.
	latest atomic.Pointer[policysync.StatusEvent]
}

func newConductorPolicyStatusReporter(cfg *config.Config, client policysync.HTTPDoer, cache *applycache.Cache) (*conductorPolicyStatusReporter, error) {
	if cfg == nil || !cfg.Conductor.Enabled {
		return nil, nil
	}
	if client == nil {
		return nil, errors.New("conductor runtime status reporter HTTP client required")
	}
	markerPath := filepath.Join(cfg.Conductor.BundleCacheDir, conductorEnrolledStateFileName)
	endpoint, err := conductorStatusEndpoint(cfg.Conductor.ConductorURL)
	if err != nil {
		return nil, err
	}
	r := &conductorPolicyStatusReporter{
		client:     client,
		endpoint:   endpoint,
		cfg:        cfg.Conductor,
		cache:      cache,
		markerPath: markerPath,
	}
	// Resolve now when the marker already exists, so an already-enrolled follower
	// behaves exactly as before and never pays a lookup on its first report.
	r.resolveIdentity()
	return r, nil
}

// resolveIdentity returns the enrollment identity, reading the marker on first
// use and caching it. A missing or unreadable marker returns false, which keeps
// the reporter silent rather than reporting under an identity it cannot prove.
// Runtime status is best-effort telemetry, so a bad marker must never fail the
// poll it rides along with.
func (r *conductorPolicyStatusReporter) resolveIdentity() (conductorEnrollmentMarker, bool) {
	if r == nil {
		return conductorEnrollmentMarker{}, false
	}
	if cached := r.identity.Load(); cached != nil {
		return *cached, true
	}
	marker, ok, err := readConductorEnrollmentMarker(r.markerPath, r.cfg)
	if err != nil || !ok {
		return conductorEnrollmentMarker{}, false
	}
	r.identity.Store(&marker)
	return marker, true
}

func conductorStatusEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("parse conductor status base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("conductor status base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("conductor status base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("conductor status base URL must not include a path component")
	}
	u.Path = controlplane.FollowerRuntimeStatusPath
	u.RawPath = ""
	return u.String(), nil
}

func (r *conductorPolicyStatusReporter) ReportPolicyStatus(ctx context.Context, ev policysync.StatusEvent) error {
	if r == nil {
		return nil
	}
	// Publish the latest poll outcome for the signed applied-state provider
	// before doing the (potentially slow) unsigned POST, so the two views track
	// the same event.
	evCopy := ev
	r.latest.Store(&evCopy)
	// The applied-state provider above works without an identity, so latest is
	// stored first and unconditionally. The POST below cannot be: without a
	// resolved enrollment identity there is nothing to report under, so stay
	// silent until the marker appears rather than posting an unattributed status.
	identity, ok := r.resolveIdentity()
	if !ok {
		return nil
	}
	status := r.status(ev, identity)
	body, err := json.Marshal(struct {
		Status controlplane.FollowerRuntimeStatus `json:"status"`
	}{Status: status})
	if err != nil {
		return fmt.Errorf("marshal conductor runtime status: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build conductor runtime status request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("post conductor runtime status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, conductorStatusResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("conductor runtime status rejected HTTP %d: %s", resp.StatusCode, statusSnippet(respBody))
	}
	return nil
}

func (r *conductorPolicyStatusReporter) status(ev policysync.StatusEvent, identity conductorEnrollmentMarker) controlplane.FollowerRuntimeStatus {
	applied := r.buildAppliedState(ev)
	return controlplane.FollowerRuntimeStatus{
		OrgID:                          r.cfg.OrgID,
		FleetID:                        r.cfg.FleetID,
		InstanceID:                     r.cfg.InstanceID,
		Environment:                    identity.Environment,
		PipelockVersion:                applied.PipelockVersion,
		GitCommit:                      applied.GitCommit,
		BuildDate:                      applied.BuildDate,
		SchemaVersion:                  conductor.SchemaVersion,
		ActiveBundleID:                 applied.ActiveBundleID,
		ActiveBundleVersion:            applied.ActiveBundleVersion,
		ActiveBundleHash:               applied.ActiveBundleHash,
		ActiveBundleMinPipelockVersion: applied.ActiveBundleMinPipelockVersion,
		LastPolicyPollAt:               applied.LastPolicyPollAt,
		LastSuccessfulApplyAt:          applied.LastSuccessfulApplyAt,
		LastApplyErrorCode:             applied.LastApplyErrorCode,
		LastApplyErrorMessage:          applied.LastApplyErrorMessage,
		LastSeenAt:                     applied.ObservedAt,
	}
}

// buildAppliedState is the SINGLE derivation of what this follower is running,
// shared by the unsigned runtime-status POST and the signed audit-batch
// applied-state so the two views never drift. It reads the same source the
// status POST always used (applycache.Cache.Active + the poll StatusEvent) and
// produces already-sanitized, bounds-satisfying values so conductor-side
// FollowerAppliedState.Validate never fails a legitimate batch closed.
func (r *conductorPolicyStatusReporter) buildAppliedState(ev policysync.StatusEvent) conductor.FollowerAppliedState {
	pollAt := ev.PollAt
	if pollAt.IsZero() {
		pollAt = time.Now().UTC()
	}
	applied := conductor.FollowerAppliedState{
		PipelockVersion:  boundAppliedStateString(cliutil.Version),
		GitCommit:        boundAppliedStateString(cliutil.GitCommit),
		BuildDate:        boundAppliedStateString(cliutil.BuildDate),
		LastPolicyPollAt: pollAt.UTC(),
		ObservedAt:       pollAt.UTC(),
		ProvenanceAt:     time.Now().UTC(),
	}
	if ev.ApplyError != nil {
		applied.LastApplyErrorCode = boundAppliedStateString(applyErrorCode(ev.ApplyError))
		applied.LastApplyErrorMessage = sanitizeAppliedStateMessage(ev.ApplyError.Error())
	}
	if ev.AppliedBundle != nil {
		applied.LastSuccessfulApplyAt = pollAt.UTC()
	}
	if r.cache != nil {
		if active, err := r.cache.Active(); err == nil {
			applied.ActiveBundleID = boundAppliedStateString(active.Bundle.BundleID)
			applied.ActiveBundleVersion = active.Bundle.Version
			applied.ActiveBundleHash = strings.ToLower(active.BundleHash)
			applied.ActiveBundleMinPipelockVersion = boundAppliedStateString(active.Bundle.MinPipelockVersion)
		}
	}
	return applied
}

// appliedStateProvider returns the callback the audit producer calls to attach
// applied-state to a signed batch. It reads the latest observed poll outcome
// (or a zero event, before the first poll) and derives applied-state from the
// live cache. It always reports ok=true: even with no active bundle yet the
// version/timestamps are worth signing, and ObservedAt is always set.
func (r *conductorPolicyStatusReporter) appliedStateProvider() func() (conductor.FollowerAppliedState, bool) {
	if r == nil {
		return nil
	}
	return func() (conductor.FollowerAppliedState, bool) {
		var ev policysync.StatusEvent
		if latest := r.latest.Load(); latest != nil {
			ev = *latest
		}
		return r.buildAppliedState(ev), true
	}
}

// boundAppliedStateString truncates a short applied-state field to the shared
// byte cap so a pathological build string can never fail the whole batch. It is
// the producer-side complement to conductor.validateAppliedStateString (the
// ingest-side backstop). Truncation is byte-safe: it trims back to a rune
// boundary so it never emits invalid UTF-8.
func boundAppliedStateString(s string) string {
	if len(s) <= conductor.MaxRuntimeStringBytes {
		return s
	}
	cut := conductor.MaxRuntimeStringBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// sanitizeAppliedStateMessage strips control characters and bounds the free-form
// apply error message to the shared rune cap, so it always satisfies
// conductor.FollowerAppliedState.Validate without dropping the batch over a
// cosmetic error string.
func sanitizeAppliedStateMessage(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= conductor.MaxApplyErrorMessageRunes {
		return s
	}
	runes := []rune(s)
	return strings.TrimSpace(string(runes[:conductor.MaxApplyErrorMessageRunes]))
}

func applyErrorCode(err error) string {
	switch {
	case errors.Is(err, applycache.ErrUnsupportedMinVersion):
		return "unsupported_min_version"
	case errors.Is(err, conductor.ErrAudienceMismatch):
		return "audience_mismatch"
	case errors.Is(err, conductor.ErrSignatureVerification):
		return "signature_verification"
	case errors.Is(err, applycache.ErrRollbackRequired):
		return "rollback_required"
	case errors.Is(err, applycache.ErrEntitlementLost):
		return "entitlement_lost"
	default:
		return "apply_failed"
	}
}

func statusSnippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	const maxLen = 256
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}
