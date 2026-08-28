//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/enrollmentclient"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func newAppliedStateReporter(t *testing.T) *conductorPolicyStatusReporter {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{Conductor: config.Conductor{
		Enabled:           true,
		ConductorURL:      "https://conductor.example",
		OrgID:             "org-main",
		FleetID:           "prod",
		InstanceID:        "pl-prod-1",
		AuditSigningKeyID: "audit-key-main-1",
		BundleCacheDir:    dir,
	}}
	if err := writeConductorEnrollmentMarker(filepath.Join(dir, conductorEnrolledStateFileName), enrollmentclient.Response{
		OrgID:       cfg.Conductor.OrgID,
		FleetID:     cfg.Conductor.FleetID,
		InstanceID:  cfg.Conductor.InstanceID,
		Environment: "prod",
		AuditKeyID:  cfg.Conductor.AuditSigningKeyID,
		EnrolledAt:  time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("writeConductorEnrollmentMarker() error = %v", err)
	}
	reporter, err := newConductorPolicyStatusReporter(cfg, statusReporterDoer{fn: func(*http.Request) (*http.Response, error) {
		return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
	}}, nil)
	if err != nil {
		t.Fatalf("newConductorPolicyStatusReporter() error = %v", err)
	}
	if reporter == nil {
		t.Fatal("reporter = nil")
	}
	return reporter
}

func TestAppliedStateProvider_ValidBeforeAnyPoll(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	provider := reporter.appliedStateProvider()
	state, ok := provider()
	if !ok {
		t.Fatal("provider ok = false, want true")
	}
	if state.ObservedAt.IsZero() {
		t.Fatal("ObservedAt not set before first poll")
	}
	if state.ProvenanceAt.IsZero() {
		t.Fatal("ProvenanceAt not set before first poll")
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("applied-state before first poll is invalid: %v", err)
	}
}

func TestAppliedStateProvider_SeparatesPollObservationFromProvenanceTime(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	pollAt := time.Date(2026, 5, 24, 12, 30, 0, 0, time.UTC)
	before := time.Now().UTC()
	state := reporter.buildAppliedState(policysync.StatusEvent{PollAt: pollAt})
	after := time.Now().UTC()
	if !state.ObservedAt.Equal(pollAt) {
		t.Fatalf("ObservedAt = %v, want poll time %v", state.ObservedAt, pollAt)
	}
	if state.ProvenanceAt.Before(before) || state.ProvenanceAt.After(after) {
		t.Fatalf("ProvenanceAt = %v, want construction time between %v and %v", state.ProvenanceAt, before, after)
	}
	if state.ProvenanceAt.Equal(state.ObservedAt) {
		t.Fatalf("ProvenanceAt = ObservedAt = %v, want separate provenance freshness", state.ProvenanceAt)
	}
}

func TestAppliedStateProvider_SanitizesErrorMessageStaysValid(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	pollAt := time.Date(2026, 5, 24, 12, 30, 0, 0, time.UTC)
	// Control characters + oversized message: the builder must sanitize/bound so
	// the signed applied-state still passes conductor-side Validate (never drops
	// the batch over a cosmetic error string).
	dirtyMsg := "line1\nline2\ttab\x00null " + strings.Repeat("x", conductor.MaxApplyErrorMessageRunes+50)
	if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{
		PollAt:     pollAt,
		ApplyError: errors.New(dirtyMsg),
	}); err != nil {
		t.Fatalf("ReportPolicyStatus() error = %v", err)
	}
	state, ok := reporter.appliedStateProvider()()
	if !ok {
		t.Fatal("provider ok = false")
	}
	if strings.ContainsAny(state.LastApplyErrorMessage, "\n\t\x00") {
		t.Fatalf("error message not sanitized: %q", state.LastApplyErrorMessage)
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("sanitized applied-state invalid: %v", err)
	}
}

func TestAppliedStateHeartbeat_EmitsOnIdlePolicyPollWhenNegotiated(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	var heartbeat conductor.AppliedStateHeartbeat
	reporter.client = statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case controlplane.FollowerRuntimeStatusPath:
			return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
		case controlplane.AppliedStateHeartbeatPath:
			body, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				t.Fatalf("read heartbeat body: %v", readErr)
			}
			if unmarshalErr := json.Unmarshal(body, &heartbeat); unmarshalErr != nil {
				t.Fatalf("decode heartbeat: %v", unmarshalErr)
			}
			return responseWithBody(http.StatusAccepted, `{"status":"accepted"}`), nil
		default:
			t.Fatalf("unexpected request path %s", req.URL.Path)
			return nil, errors.New("unreachable")
		}
	}}

	pollAt := time.Now().UTC().Add(-4 * time.Minute)
	if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{PollAt: pollAt}); err != nil {
		t.Fatalf("ReportPolicyStatus() error = %v", err)
	}
	if heartbeat.HeartbeatID == "" {
		t.Fatal("signed heartbeat was not emitted")
	}
	if !heartbeat.AppliedState.LastPolicyPollAt.Equal(pollAt) {
		t.Fatalf("LastPolicyPollAt = %v, want %v", heartbeat.AppliedState.LastPolicyPollAt, pollAt)
	}
	if time.Since(heartbeat.AppliedState.ObservedAt) > time.Minute {
		t.Fatalf("ObservedAt = %v, want fresh heartbeat time", heartbeat.AppliedState.ObservedAt)
	}
	if err := heartbeat.VerifySignaturesAt(time.Now().UTC(), func(id string) (conductor.SignatureKey, error) {
		if id != "audit-key-main-1" {
			return conductor.SignatureKey{}, errors.New("unknown key")
		}
		return conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
	}); err != nil {
		t.Fatalf("VerifySignaturesAt() error = %v", err)
	}
}

func TestAppliedStateHeartbeat_FailureDoesNotFailRuntimeStatus(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	statusRequests := 0
	heartbeatRequests := 0
	reporter.client = statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case controlplane.FollowerRuntimeStatusPath:
			statusRequests++
			return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
		case controlplane.AppliedStateHeartbeatPath:
			heartbeatRequests++
			return nil, errors.New("heartbeat unavailable")
		default:
			t.Fatalf("unexpected request path %s", req.URL.Path)
			return nil, errors.New("unreachable")
		}
	}}
	if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{PollAt: time.Now().UTC()}); err != nil {
		t.Fatalf("ReportPolicyStatus() error = %v, want nil after successful runtime status", err)
	}
	if statusRequests != 1 || heartbeatRequests != 1 {
		t.Fatalf("requests = status %d, heartbeat %d; want 1 each", statusRequests, heartbeatRequests)
	}
}

func TestAppliedStateHeartbeat_RemainsOffWithoutNegotiation(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	// A downgrade/reload must clear a previously negotiated signer, not leave
	// the old heartbeat capability active in memory.
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	reporter.configureAppliedStateHeartbeat(false, "audit-key-main-1", priv)
	requests := 0
	reporter.client = statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		requests++
		if req.URL.Path != controlplane.FollowerRuntimeStatusPath {
			t.Fatalf("unexpected unnegotiated request path %s", req.URL.Path)
		}
		return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
	}}
	if err := reporter.ReportPolicyStatus(context.Background(), policysync.StatusEvent{PollAt: time.Now().UTC()}); err != nil {
		t.Fatalf("ReportPolicyStatus() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want only unsigned status", requests)
	}
}

func TestAppliedStateHeartbeat_CurrentSnapshot(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	wantPoll := time.Now().UTC().Add(-time.Minute)
	reporter.latest.Store(&policysync.StatusEvent{PollAt: wantPoll})
	var got conductor.AppliedStateHeartbeat
	reporter.client = statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatalf("decode heartbeat: %v", err)
		}
		return responseWithBody(http.StatusAccepted, `{"status":"accepted"}`), nil
	}}
	if err := reporter.reportCurrentAppliedStateHeartbeat(context.Background()); err != nil {
		t.Fatalf("reportCurrentAppliedStateHeartbeat() error = %v", err)
	}
	if !got.AppliedState.LastPolicyPollAt.Equal(wantPoll) {
		t.Fatalf("LastPolicyPollAt = %v, want %v", got.AppliedState.LastPolicyPollAt, wantPoll)
	}
}

func TestAppliedStateHeartbeat_CurrentSnapshotWaitsForFirstPoll(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	requests := 0
	reporter.client = statusReporterDoer{fn: func(*http.Request) (*http.Response, error) {
		requests++
		return responseWithBody(http.StatusAccepted, `{"status":"accepted"}`), nil
	}}
	if err := reporter.reportCurrentAppliedStateHeartbeat(context.Background()); err != nil {
		t.Fatalf("reportCurrentAppliedStateHeartbeat() error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("heartbeat requests before first policy poll = %d, want 0", requests)
	}
}

// TestAppliedStateProvider_MatchesUnsignedStatus proves the signed applied-state
// and the unsigned runtime-status POST derive from one source, so the two fleet
// views never disagree on what the follower is running.
func TestAppliedStateProvider_MatchesUnsignedStatus(t *testing.T) {
	reporter := newAppliedStateReporter(t)
	ev := policysync.StatusEvent{
		PollAt:        time.Date(2026, 5, 24, 12, 30, 0, 0, time.UTC),
		AppliedBundle: &conductor.PolicyBundle{BundleID: "bundle-1"},
		ApplyError:    applycache.ErrRollbackRequired,
	}
	identity, ok := reporter.resolveIdentity()
	if !ok {
		t.Fatal("reporter did not resolve its enrollment identity from the marker written above")
	}
	unsigned := reporter.status(ev, identity)
	applied := reporter.buildAppliedState(ev)
	if unsigned.PipelockVersion != applied.PipelockVersion ||
		unsigned.GitCommit != applied.GitCommit ||
		unsigned.BuildDate != applied.BuildDate ||
		unsigned.LastApplyErrorCode != applied.LastApplyErrorCode ||
		unsigned.LastApplyErrorMessage != applied.LastApplyErrorMessage ||
		unsigned.ActiveBundleID != applied.ActiveBundleID ||
		unsigned.ActiveBundleVersion != applied.ActiveBundleVersion ||
		!unsigned.LastPolicyPollAt.Equal(applied.LastPolicyPollAt) ||
		!unsigned.LastSuccessfulApplyAt.Equal(applied.LastSuccessfulApplyAt) {
		t.Fatalf("unsigned status and signed applied-state diverged:\n unsigned=%+v\n applied=%+v", unsigned, applied)
	}
}
