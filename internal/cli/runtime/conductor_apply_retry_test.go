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
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestConductorApplyRetryAfterInterruptedRestore(t *testing.T) {
	s, signer := newConductorApplyTestServer(t)
	first := signedRuntimePolicyBundle(t, signer, "first", 1, "", "mode: balanced\n")
	applied, err := s.ApplyConductorPolicyBundle(first, ConductorApplyOptions{Resolver: signer.resolver()})
	if err != nil {
		t.Fatal(err)
	}
	next := signedRuntimePolicyBundle(t, signer, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
	hash, err := next.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(s.proxy.CurrentConfig().Conductor.BundleCacheDir, "configs", hash+".yaml")
	swaps := 0
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		swaps++
		switch swaps {
		case 1:
			if err := os.Remove(target); err != nil {
				t.Error(err)
			}
		case 2:
			// Keep the last candidate success inside the deduplication window.
			s.stateMu.Lock()
			s.lastReloadAt = time.Now().Add(time.Hour)
			s.stateMu.Unlock()
			panic("synthetic interruption during restoration")
		}
	})
	t.Cleanup(restore)
	_, err = s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()})
	if !errors.Is(err, applycache.ErrLivePolicyUncertain) || swaps != 2 {
		t.Fatalf("fixture did not interrupt restoration: swaps=%d error=%v", swaps, err)
	}
	if s.proxy.CurrentConfig().Mode != config.ModeBalanced || !s.killswitch.ConductorApplyFailure() {
		t.Fatal("fixture did not leave restored policy under uncertain admission")
	}
	restore()
	if _, err := s.ApplyConductorPolicyBundle(next, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	active, err := s.applyCache().Active()
	if err != nil || active.Bundle.Version != 2 {
		t.Fatalf("active version=%d error=%v", active.Bundle.Version, err)
	}
	if s.proxy.CurrentConfig().Mode != config.ModeStrict {
		t.Fatal("retry committed strict policy while the running proxy remained balanced")
	}
	if s.killswitch.ConductorApplyFailure() {
		t.Fatal("successful retry retained uncertainty")
	}
}
