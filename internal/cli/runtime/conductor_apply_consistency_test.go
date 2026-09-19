//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/policysync"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestConductorApplyActivationFailureRestoresPriorLivePolicy(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatalf("apply first policy: %v", err)
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	nextHash, err := next.CanonicalHash()
	if err != nil {
		t.Fatalf("hash next policy: %v", err)
	}
	target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", nextHash+".yaml")
	removedCandidate := false
	restoreHook := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s || removedCandidate {
			return
		}
		removedCandidate = true
		if err := os.Remove(target); err != nil {
			t.Errorf("remove staged candidate: %v", err)
		}
	})
	t.Cleanup(restoreHook)

	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err == nil {
		t.Fatal("apply candidate = nil, want activation error")
	}
	if got := s.proxy.CurrentConfig().Mode; got != config.ModeBalanced {
		t.Fatalf("live mode after failed activation = %s, want prior balanced mode", got)
	}
	active, err := s.applyCache().Active()
	if err != nil {
		t.Fatalf("read durable active policy: %v", err)
	}
	if active.Bundle.Version != 1 {
		t.Fatalf("durable version after failed activation = %d, want 1", active.Bundle.Version)
	}
	s.conductorStale.(*applycache.StaleEnforcer).CheckNow()
	if decision := s.killswitch.IsActiveForIP("203.0.113.7"); decision.Active {
		t.Fatalf("admission after restored prior policy = %+v, want allowed", decision)
	}
}

func TestConductorApplyUncertainStateDeniesAndReportsWithoutActiveClaim(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatalf("apply first policy: %v", err)
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	nextHash, err := next.CanonicalHash()
	if err != nil {
		t.Fatalf("hash next policy: %v", err)
	}
	target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", nextHash+".yaml")
	originalConstructor := s.scannerConstructor
	restoreHook := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		if err := os.Remove(target); err != nil {
			t.Errorf("remove staged candidate: %v", err)
		}
		s.scannerConstructor = func(*config.Config) (*scanner.Scanner, error) {
			return nil, errors.New("restore scanner construction failure")
		}
	})
	t.Cleanup(func() {
		restoreHook()
		s.scannerConstructor = originalConstructor
	})

	_, applyErr := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
	if !errors.Is(applyErr, applycache.ErrLivePolicyUncertain) {
		t.Fatalf("apply candidate error = %v, want ErrLivePolicyUncertain", applyErr)
	}
	s.conductorStale.(*applycache.StaleEnforcer).CheckNow()
	decision := s.killswitch.IsActiveForIP("203.0.113.7")
	if !decision.Active || decision.Source != "conductor_apply_failure" {
		t.Fatalf("admission after unresolved apply = %+v, want conductor_apply_failure deny", decision)
	}
	reporter, err := newConductorPolicyStatusReporter(s.proxy.CurrentConfig(), statusReporterDoer{}, s.applyCache(), s.conductorActiveSnapshot)
	if err != nil {
		t.Fatalf("new status reporter: %v", err)
	}
	state := reporter.buildAppliedState(conductorStatusEvent(t))
	if state.ActiveBundleID != "" || state.ActiveBundleVersion != 0 || state.ActiveBundleHash != "" {
		t.Fatalf("uncertain applied state claimed active bundle: %+v", state)
	}
	if state.LastApplyErrorCode != "apply_failed" {
		t.Fatalf("uncertain applied-state error code = %q, want apply_failed", state.LastApplyErrorCode)
	}

	restoreHook()
	s.scannerConstructor = originalConstructor
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("retry policy after restoring runtime: %v", err)
	}
	if decision := s.killswitch.IsActiveForIP("203.0.113.7"); decision.Active {
		t.Fatalf("admission after successful retry = %+v, want allowed", decision)
	}
}

func conductorStatusEvent(t *testing.T) policysync.StatusEvent {
	t.Helper()
	return policysync.StatusEvent{PollAt: time.Date(2026, time.September, 19, 0, 0, 0, 0, time.UTC)}
}
