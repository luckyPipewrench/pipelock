//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestConductorActiveSnapshotRequiresConsistentRuntime(t *testing.T) {
	var absent *Server
	absent.setConductorApplyConsistency(nil)
	if absent.conductorApplyConsistencyError() != nil {
		t.Fatal("nil server reported an apply error")
	}
	if _, err := absent.conductorActiveSnapshot(); !errors.Is(err, applycache.ErrLivePolicyUncertain) {
		t.Fatalf("nil runtime snapshot = %v", err)
	}
	empty := &Server{killswitch: killswitch.New(config.Defaults())}
	if _, err := empty.conductorActiveSnapshot(); !errors.Is(err, applycache.ErrCacheRequired) {
		t.Fatalf("missing cache snapshot = %v", err)
	}
	empty.setConductorApplyConsistency(applycache.ErrLivePolicyUncertain)
	if _, err := empty.conductorActiveSnapshot(); !errors.Is(err, applycache.ErrLivePolicyUncertain) {
		t.Fatalf("uncertain snapshot = %v", err)
	}
	empty.setConductorApplyConsistency(nil)
	if empty.conductorApplyConsistencyError() != nil {
		t.Fatal("consistency reset retained an error")
	}

	s, signer := newConductorApplyTestServer(t)
	if _, err := s.conductorActiveSnapshot(); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("empty real cache = %v", err)
	}
	bundle := signedRuntimePolicyBundle(t, signer, "snapshot", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	s.conductorApplyMu.Lock()
	_, lockedErr := s.conductorActiveSnapshot()
	s.conductorApplyMu.Unlock()
	if !errors.Is(lockedErr, errConductorSnapshotBusy) {
		t.Fatalf("snapshot during apply = %v", lockedErr)
	}
	snapshot, err := s.conductorActiveSnapshot()
	if err != nil || snapshot.BundleHash != applied.BundleHash {
		t.Fatalf("healthy snapshot hash=%s error=%v", snapshot.BundleHash, err)
	}
}

func TestConductorApplySignedHeartbeatOmitsUncertainPolicy(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	bundle := signedRuntimePolicyBundle(t, signer, "heartbeat", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	reporter := newAppliedStateReporter(t)
	reporter.activeSnapshot = s.conductorActiveSnapshot
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.configureAppliedStateHeartbeat(true, "audit-key-main-1", priv)
	var heartbeat conductor.AppliedStateHeartbeat
	reporter.client = statusReporterDoer{fn: func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == controlplane.AppliedStateHeartbeatPath {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(body, &heartbeat); err != nil {
				return nil, err
			}
			return responseWithBody(http.StatusAccepted, `{"status":"accepted"}`), nil
		}
		return responseWithBody(http.StatusOK, `{"status":"ok"}`), nil
	}}
	for _, uncertain := range []bool{true, false} {
		if uncertain {
			s.setConductorApplyConsistency(applycache.ErrLivePolicyUncertain)
		} else {
			s.setConductorApplyConsistency(nil)
		}
		heartbeat = conductor.AppliedStateHeartbeat{}
		if err := reporter.ReportPolicyStatus(t.Context(), policysync.StatusEvent{PollAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if heartbeat.HeartbeatID == "" {
			t.Fatal("no signed heartbeat was emitted")
		}
		if err := heartbeat.VerifySignaturesAt(time.Now().UTC(), func(id string) (conductor.SignatureKey, error) {
			if id != "audit-key-main-1" {
				return conductor.SignatureKey{}, errors.New("unexpected signer")
			}
			return conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
		}); err != nil {
			t.Fatalf("heartbeat signature: %v", err)
		}
		state := heartbeat.AppliedState
		if uncertain {
			if state.ActiveBundleID != "" || state.ActiveBundleVersion != 0 || state.ActiveBundleHash != "" || state.LastApplyErrorCode != "apply_failed" {
				t.Fatalf("signed uncertainty made an active claim: %+v", state)
			}
		} else if state.ActiveBundleHash != applied.BundleHash || state.LastApplyErrorCode != "" {
			t.Fatalf("healthy signed state did not recover: %+v", state)
		}
	}
}

func TestConductorSnapshotContentionPreservesTheLastApplyOutcome(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	bundle := signedRuntimePolicyBundle(t, signer, "snapshot-contention", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	reporter := s.conductorStatusReporter.(*conductorPolicyStatusReporter)
	for _, failed := range []bool{false, true} {
		event := policysync.StatusEvent{PollAt: time.Now().UTC()}
		if failed {
			event.ApplyError = errors.New("previous apply was refused")
		}
		s.conductorApplyMu.Lock()
		state := reporter.buildAppliedState(event)
		s.conductorApplyMu.Unlock()
		if state.ActiveBundleHash != "" || state.ActiveBundleID != "" || state.ActiveBundleVersion != 0 {
			t.Fatalf("contended snapshot made an active-policy claim: %+v", state)
		}
		if failed {
			if state.LastApplyErrorCode != "apply_failed" || state.LastApplyErrorMessage != event.ApplyError.Error() {
				t.Errorf("contended snapshot replaced the observed failure: %+v", state)
			}
		} else if state.LastApplyErrorCode != "" || state.LastApplyErrorMessage != "" {
			t.Errorf("contended snapshot invented an apply failure: %+v", state)
		}
		if err := state.Validate(); err != nil {
			t.Fatalf("contended snapshot violates the wire contract: %v", err)
		}
	}
	state := reporter.buildAppliedState(policysync.StatusEvent{PollAt: time.Now().UTC()})
	if state.ActiveBundleHash != applied.BundleHash || state.LastApplyErrorCode != "" {
		t.Fatalf("released snapshot did not report the committed policy: %+v", state)
	}
}
