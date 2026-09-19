//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestConductorApplyRepeatedFailureKeepsAdmissionClosed(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n  - other.vendor.example\n")
	originalConstructor := s.scannerConstructor
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			// Change policy again so the actual reload cannot take its unchanged
			// configuration shortcut. This narrows the previous live allowlist.
			next = signedRuntimePolicyBundle(t, signer, "retry", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
		}
		nextHash, err := next.CanonicalHash()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", nextHash+".yaml")
		removed := false
		restoreHook := setReloadAfterProxySwapHookForTest(func(server *Server) {
			if server != s || removed {
				return
			}
			removed = true
			if err := os.Remove(target); err != nil {
				t.Errorf("remove candidate: %v", err)
			}
			if attempt == 0 {
				s.scannerConstructor = func(*config.Config) (*scanner.Scanner, error) {
					return nil, errors.New("synthetic restoration failure")
				}
			}
		})
		t.Cleanup(restoreHook)
		_, applyErr := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
		restoreHook()
		s.scannerConstructor = originalConstructor
		if !removed {
			t.Fatalf("attempt %d: fault injection did not reach the live swap", attempt+1)
		}
		if !errors.Is(applyErr, applycache.ErrLivePolicyUncertain) {
			t.Errorf("attempt %d: error = %v, want uncertain outcome", attempt+1, applyErr)
		}
		s.conductorStale.(*applycache.StaleEnforcer).CheckNow()
		if decision := s.killswitch.IsActiveForIP("203.0.113.7"); !decision.Active {
			t.Errorf("attempt %d: admission reopened while live policy is %s", attempt+1, s.proxy.CurrentConfig().Mode)
		}
		active, err := s.applyCache().Active()
		if err != nil || active.Bundle.Version != 1 {
			t.Fatalf("attempt %d: durable state = %+v, %v; want version 1", attempt+1, active, err)
		}
	}
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("healthy retry: %v", err)
	}
	if s.killswitch.IsActiveForIP("203.0.113.7").Active {
		t.Fatal("healthy committed retry did not restore admission")
	}
}

func TestConductorApplyPostSwapPanicCannotLeaveAdmissionOpen(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	fired := false
	restoreHook := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server == s && !fired {
			fired = true
			// Keep the old success inside the dedupe window without depending
			// on how long scanner construction takes on this machine.
			s.stateMu.Lock()
			s.lastReloadAt = time.Now().Add(time.Hour)
			s.stateMu.Unlock()
			panic("synthetic failure after proxy publication")
		}
	})
	t.Cleanup(restoreHook)
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err == nil {
		t.Fatal("post-swap panic was not surfaced")
	}
	active, err := s.applyCache().Active()
	if err != nil || active.Bundle.Version != 1 {
		t.Fatalf("durable state after panic = %+v, %v", active, err)
	}
	s.conductorStale.(*applycache.StaleEnforcer).CheckNow()
	if s.proxy.CurrentConfig().Mode != config.ModeBalanced && !s.killswitch.IsActiveForIP("203.0.113.7").Active {
		t.Fatal("post-swap panic left a different live policy with admission open")
	}
}

func TestConductorApplySerializesReloadAndSuppressesPendingClaims(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	const operatorDeny = "operator-block.vendor.example"
	operatorYAML := "mode: balanced\nfetch_proxy:\n  monitoring:\n    blocklist:\n      - " + operatorDeny + "\n"
	operatorCfg, err := config.LoadPolicyBundleBytes([]byte(operatorYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := preserveConductorBundleLocalRuntimeState(s.proxy.CurrentConfig(), operatorCfg, operatorYAML); err != nil {
		t.Fatal(err)
	}
	// This is an operator-owned listener setting, preserved from local state
	// during bundle merging. Apply the operator's edit after that preservation.
	operatorCfg.FetchProxy.Monitoring.Blocklist = append(slices.Clone(operatorCfg.FetchProxy.Monitoring.Blocklist), operatorDeny)
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	nextHash, err := next.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", nextHash+".yaml")
	swapped := make(chan struct{})
	resume := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	t.Cleanup(release)
	var workers sync.WaitGroup
	restoreLockHook := func() {}
	paused := false
	restoreSwapHook := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s || paused {
			return
		}
		paused = true
		close(swapped)
		<-resume
		if err := os.Remove(target); err != nil {
			t.Errorf("remove candidate: %v", err)
		}
	})
	t.Cleanup(restoreSwapHook)
	// Join before removing hooks or closing the server, including on Fatal.
	t.Cleanup(func() {
		release()
		workers.Wait()
		restoreLockHook()
	})
	applyDone := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
		applyDone <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	select {
	case <-swapped:
	case <-ctx.Done():
		t.Fatal("apply never reached the live swap")
	}
	s.conductorStale.(*applycache.StaleEnforcer).CheckNow()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch", nil)
	request.RemoteAddr = "203.0.113.7:42000"
	if decision := s.killswitch.IsActiveHTTP(request); !decision.Active {
		t.Error("pending activation admitted HTTP traffic")
	}
	reporter, ok := s.conductorStatusReporter.(*conductorPolicyStatusReporter)
	if !ok || reporter == nil {
		t.Fatal("runtime did not wire its policy status reporter")
	}
	state, ok := reporter.appliedStateProvider()()
	if !ok || state.ActiveBundleID != "" || state.ActiveBundleVersion != 0 || state.ActiveBundleHash != "" || state.LastApplyErrorCode != "apply_failed" {
		t.Errorf("pending activation made an active-policy claim: %+v", state)
	}
	if err := state.Validate(); err != nil {
		t.Errorf("pending applied state violates its wire contract: %v", err)
	}
	operatorWaiting := make(chan struct{})
	operatorAcquired := make(chan struct{})
	restoreLockHook = setReloadLockHookForTest(func(acquired bool) {
		if acquired {
			close(operatorAcquired)
		} else {
			close(operatorWaiting)
		}
	})
	operatorDone := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		operatorDone <- s.Reload(operatorCfg)
	}()
	select {
	case <-operatorWaiting:
	case <-ctx.Done():
		t.Fatal("operator reload did not attempt the lock")
	}
	select {
	case <-operatorAcquired:
		t.Error("operator reload interleaved with an unfinished apply")
	default:
	}
	release()
	select {
	case err := <-applyDone:
		if err == nil {
			t.Error("removed candidate did not fail activation")
		}
	case <-ctx.Done():
		t.Fatal("apply failed to finish after release")
	}
	select {
	case err := <-operatorDone:
		if err != nil {
			t.Fatalf("operator reload after compensation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("operator reload remained blocked after compensation")
	}
	if !slices.Contains(s.proxy.CurrentConfig().FetchProxy.Monitoring.Blocklist, operatorDeny) {
		t.Fatal("compensation overwrote the later operator reload")
	}
}

func TestConductorApplyFirstFailureRetainsNoBundleDenial(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	hash, err := bundle.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", hash+".yaml")
	fired := false
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server == s && !fired {
			fired = true
			if err := os.Remove(target); err != nil {
				t.Error(err)
			}
		}
	})
	t.Cleanup(restore)
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err == nil {
		t.Fatal("first apply unexpectedly succeeded")
	}
	if !fired || !s.killswitch.IsActiveForIP("203.0.113.7").Active {
		t.Fatal("failed first apply admitted traffic without a durable policy")
	}
	if _, err := s.applyCache().Active(); !errors.Is(err, applycache.ErrNoValidBundle) {
		t.Fatalf("active after first failure: %v", err)
	}
	restore()
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("healthy retry: %v", err)
	}
	if s.killswitch.IsActiveForIP("203.0.113.7").Active {
		t.Fatal("healthy first apply did not restore admission")
	}
}

func TestConductorApplyCannotClearEntitlementTeardownDenial(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	if !s.conductorStaleStrictDeny.Load() {
		t.Fatal("fixture requires strict stale policy")
	}
	bundle := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server == s {
			s.teardownConductor("synthetic entitlement loss")
		}
	})
	t.Cleanup(restore)
	_, _ = s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()})
	if !s.conductorDown.Load() {
		t.Fatal("fixture did not tear down conductor")
	}
	if !s.killswitch.IsActiveForIP("203.0.113.7").Active {
		t.Fatal("completed apply cleared entitlement teardown denial")
	}
}
