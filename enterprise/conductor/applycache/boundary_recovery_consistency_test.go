//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBoundaryRecoveryKeepsUncertaintyUntilReloadCompletes(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	boundary := Boundary{
		Cache: cache, Identity: testIdentity(), Resolver: testResolver(key),
		LocalVersion: "1.2.3", Now: func() time.Time { return testNow },
		Reload: func(*config.Config) error { return nil },
	}
	applied, err := boundary.Apply(signedTestBundle(t, key, "recovery", 1, ""), ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var consistency error
	boundary.Consistency = func(err error) { consistency = err }
	reloadFailure := errors.New("interrupted runtime restoration")
	for _, fails := range []bool{true, false} {
		boundary.Reload = func(*config.Config) error {
			if !errors.Is(consistency, ErrLivePolicyUncertain) {
				t.Error("recovery published without first marking the live policy uncertain")
			}
			if fails {
				return reloadFailure
			}
			return nil
		}
		_, err := boundary.RecoverActive()
		if fails {
			if !errors.Is(err, reloadFailure) || !errors.Is(err, ErrLivePolicyUncertain) || !errors.Is(consistency, ErrLivePolicyUncertain) {
				t.Errorf("failed recovery did not retain uncertainty: error=%v consistency=%v", err, consistency)
			}
		} else if err != nil || consistency != nil {
			t.Errorf("healthy recovery did not clear uncertainty: error=%v consistency=%v", err, consistency)
		}
		active, err := cache.Active()
		if err != nil || active.BundleHash != applied.BundleHash {
			t.Fatalf("recovery changed durable policy: %v", err)
		}
	}
}

func TestBoundaryApplyCompensatesOnlyPublishedReloadErrors(t *testing.T) {
	for _, published := range []bool{false, true} {
		name := "before publication"
		if published {
			name = "after publication"
		}
		t.Run(name, func(t *testing.T) {
			key := newTestKey(t)
			cache := openTestCache(t)
			live := config.ModeBalanced
			boundary := Boundary{
				Cache: cache, Identity: testIdentity(), Resolver: testResolver(key),
				LocalVersion: "1.2.3", Now: func() time.Time { return testNow },
				Reload: func(cfg *config.Config) error { live = cfg.Mode; return nil },
			}
			first := signedBoundaryBundle(t, key, "first", 1, "", "mode: balanced\n")
			applied, err := boundary.Apply(first, ApplyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("interrupted candidate reload")
			boundary.Reload = func(cfg *config.Config) error {
				if published {
					live = cfg.Mode
				}
				return failure
			}
			boundary.ReloadChanged = func() bool { return live != config.ModeBalanced }
			restored := false
			boundary.Restore = func() error {
				restored = true
				live = config.ModeBalanced
				return nil
			}
			next := signedBoundaryBundle(t, key, "next", 2, applied.BundleHash, "mode: strict\napi_allowlist:\n  - api.vendor.example\n")
			if _, err := boundary.Apply(next, ApplyOptions{}); !errors.Is(err, failure) || errors.Is(err, ErrLivePolicyUncertain) {
				t.Fatalf("candidate reload error = %v", err)
			}
			if restored != published || live != config.ModeBalanced {
				t.Fatalf("compensation: restored=%v live=%s", restored, live)
			}
			active, err := cache.Active()
			if err != nil || active.BundleHash != applied.BundleHash {
				t.Fatalf("failed reload changed durable policy: %v", err)
			}
		})
	}
}
