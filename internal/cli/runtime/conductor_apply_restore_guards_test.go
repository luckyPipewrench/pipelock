//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
)

func TestConductorApplyRestoresPriorEnforcementAfterActivationError(t *testing.T) {
	s, signer := newConductorApplyTestServerWithConfig(t, "enforce: false")
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\nenforce: false\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	previous := s.proxy.CurrentConfig().Clone()
	if previous.EnforceEnabled() {
		t.Fatal("fixture did not start with enforcement disabled")
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: balanced\nenforce: true\n")
	hash, err := next.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(previous.Conductor.BundleCacheDir, "configs", hash+".yaml")
	fired := false
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s || fired {
			return
		}
		fired = true
		if !s.proxy.CurrentConfig().EnforceEnabled() {
			t.Error("candidate did not enable enforcement before activation")
		}
		if err := os.Remove(target); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	_, err = s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
	if !fired || err == nil || errors.Is(err, applycache.ErrLivePolicyUncertain) {
		t.Fatalf("prior enforcement was not restored: fired=%v error=%v", fired, err)
	}
	if s.proxy.CurrentConfig().CanonicalPolicyHash() != previous.CanonicalPolicyHash() || s.killswitch.ConductorApplyFailure() {
		t.Fatal("failed activation did not restore the exact prior policy and admission")
	}
	active, err := s.applyCache().Active()
	if err != nil || active.BundleHash != applied.BundleHash {
		t.Fatalf("failed activation changed durable state: %v", err)
	}
	restore()
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("healthy apply: %v", err)
	}
	if err := s.Reload(previous.Clone()); err == nil || !strings.Contains(err.Error(), "enforce disabled") {
		t.Fatalf("ordinary reload lost its enforcement guard: %v", err)
	}
	if !s.proxy.CurrentConfig().EnforceEnabled() {
		t.Fatal("rejected ordinary reload disabled enforcement")
	}
}

func TestConductorApplyRestoresPriorRuleCoverageAfterActivationError(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)
	s, signer := newConductorApplyTestServer(t)
	const baseline = "mode: balanced\napi_allowlist:\n  - api.vendor.example\n"
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", baseline)
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	previous := s.proxy.CurrentConfig().Clone()
	bundleDir := installServerTestDLPBundle(t, dataDir, "")
	removedDir := filepath.Join(t.TempDir(), "retained-bundle")
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	hash, err := next.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(previous.Conductor.BundleCacheDir, "configs", hash+".yaml")
	fired := false
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s || fired {
			return
		}
		fired = true
		live := s.proxy.CurrentConfig()
		if pattern, ok := dlpByName(live.DLP.Patterns, "community-dlp:dlp-secret"); !ok || pattern.Bundle != "community-dlp" {
			t.Error("candidate did not load the added rule bundle")
		}
		if err := os.Remove(target); err != nil {
			t.Error(err)
		}
		if err := os.Rename(bundleDir, removedDir); err != nil {
			t.Error(err)
		}
	})
	t.Cleanup(restore)
	_, err = s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
	if !fired || err == nil || errors.Is(err, applycache.ErrLivePolicyUncertain) {
		t.Fatalf("prior rule coverage was not restored: fired=%v error=%v", fired, err)
	}
	if s.proxy.CurrentConfig().CanonicalPolicyHash() != previous.CanonicalPolicyHash() || s.killswitch.ConductorApplyFailure() {
		t.Fatal("failed activation did not restore prior rule coverage and admission")
	}
	active, err := s.applyCache().Active()
	if err != nil || active.BundleHash != applied.BundleHash {
		t.Fatalf("failed activation changed durable state: %v", err)
	}
	restore()
	if err := os.Rename(removedDir, bundleDir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("healthy apply: %v", err)
	}
	if err := os.Rename(bundleDir, removedDir); err != nil {
		t.Fatal(err)
	}
	s.stateMu.Lock()
	s.lastReloadAt = time.Time{}
	s.stateMu.Unlock()
	if err := s.Reload(previous.Clone()); err == nil || !strings.Contains(err.Error(), "strict mode rule bundle coverage drop") {
		t.Fatalf("ordinary reload lost its rule coverage guard: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if pattern, ok := dlpByName(live.DLP.Patterns, "community-dlp:dlp-secret"); !ok || pattern.Bundle != "community-dlp" {
		t.Fatal("rejected ordinary reload discarded bundle coverage")
	}
}

func TestConductorApplyRetainsDenialWhenPriorRuleCoverageIsUnavailable(t *testing.T) {
	for _, kind := range []string{"dlp", "tool-poison"} {
		t.Run(kind, func(t *testing.T) {
			dataDir := t.TempDir()
			t.Setenv("XDG_DATA_HOME", dataDir)
			s, signer := newConductorApplyTestServer(t)
			var bundleDir string
			if kind == "dlp" {
				bundleDir = installServerTestDLPBundle(t, dataDir, "")
			} else {
				bundleDir = installServerTestToolPoisonBundle(t, dataDir)
			}
			first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
			applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
			if err != nil {
				t.Fatal(err)
			}
			if kind == "dlp" {
				if _, ok := dlpByName(s.proxy.CurrentConfig().DLP.Patterns, "community-dlp:dlp-secret"); !ok {
					t.Fatal("baseline did not load its DLP coverage")
				}
			} else if len(s.currentMCPToolExtraPoison()) != 1 {
				t.Fatal("baseline did not load its tool-poison coverage")
			}
			next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
			hash, err := next.CanonicalHash()
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", hash+".yaml")
			retainedDir := filepath.Join(t.TempDir(), "retained-bundle")
			fired := false
			restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
				if server != s || fired {
					return
				}
				fired = true
				if err := os.Remove(target); err != nil {
					t.Error(err)
				}
				if err := os.Rename(bundleDir, retainedDir); err != nil {
					t.Error(err)
				}
			})
			t.Cleanup(restore)
			_, err = s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
			if !fired || !errors.Is(err, applycache.ErrLivePolicyUncertain) || !s.killswitch.ConductorApplyFailure() {
				t.Fatalf("missing prior coverage was reported as restored: fired=%v error=%v", fired, err)
			}
			state := s.conductorStatusReporter.(*conductorPolicyStatusReporter).buildAppliedState(conductorStatusEvent(t))
			if state.ActiveBundleHash != "" || state.LastApplyErrorCode != "apply_failed" {
				t.Fatalf("unrestored coverage made an active policy claim: %+v", state)
			}
			active, err := s.applyCache().Active()
			if err != nil || active.BundleHash != applied.BundleHash {
				t.Fatalf("unrestored coverage changed durable policy: %v", err)
			}
			restore()
			if err := os.Rename(retainedDir, bundleDir); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
				t.Fatalf("healthy retry after coverage restoration: %v", err)
			}
			if s.killswitch.ConductorApplyFailure() {
				t.Fatal("healthy retry retained the uncertainty denial")
			}
		})
	}
}
