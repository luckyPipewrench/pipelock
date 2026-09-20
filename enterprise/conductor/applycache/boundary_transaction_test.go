//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBoundaryApplyRestoresPriorLivePolicyAfterActivationFailure(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	first := signedTestBundle(t, key, "first", 1, "")
	firstHash, err := first.CanonicalHash()
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	next := signedBoundaryBundle(t, key, "next", 2, firstHash, "mode: balanced\n")
	nextHash, err := next.CanonicalHash()
	if err != nil {
		t.Fatalf("hash next policy: %v", err)
	}
	liveMode := config.ModeStrict
	removedCandidate := false
	var consistency error
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(cfg *config.Config) error {
			liveMode = cfg.Mode
			if cfg.Mode == config.ModeBalanced && !removedCandidate {
				removedCandidate = true
				return os.Remove(filepath.Join(cache.configsDir, nextHash+configExt))
			}
			return nil
		},
		Restore: func() error {
			liveMode = config.ModeStrict
			return nil
		},
		Consistency: func(err error) { consistency = err },
	}
	if _, err := boundary.Apply(first, ApplyOptions{}); err != nil {
		t.Fatalf("apply first policy: %v", err)
	}
	if _, err := boundary.Apply(next, ApplyOptions{}); err == nil {
		t.Fatal("apply candidate = nil, want activation error")
	}
	if liveMode != config.ModeStrict {
		t.Fatalf("live mode after activation failure = %s, want restored strict", liveMode)
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("read active policy: %v", err)
	}
	if active.Bundle.Version != 1 {
		t.Fatalf("active version after activation failure = %d, want 1", active.Bundle.Version)
	}
	if consistency != nil {
		t.Fatalf("consistency after restored failure = %v, want nil", consistency)
	}
	if _, err := boundary.Apply(next, ApplyOptions{}); err != nil {
		t.Fatalf("retry candidate after restoration: %v", err)
	}
	if liveMode != config.ModeBalanced {
		t.Fatalf("live mode after retry = %s, want balanced", liveMode)
	}
}

func TestBoundaryApplyPostRenameWriteErrorRetriesDurability(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	first := signedTestBundle(t, key, "first", 1, "")
	firstHash, err := first.CanonicalHash()
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	next := signedBoundaryBundle(t, key, "next", 2, firstHash, "mode: balanced\n")
	liveMode := config.ModeStrict
	var consistency error
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(cfg *config.Config) error {
			liveMode = cfg.Mode
			return nil
		},
		Restore: func() error {
			liveMode = config.ModeStrict
			return nil
		},
		Consistency: func(err error) { consistency = err },
	}
	if _, err := boundary.Apply(first, ApplyOptions{}); err != nil {
		t.Fatalf("apply first policy: %v", err)
	}
	activePath := filepath.Join(cache.dir, activeRecordName)
	failOnce := true
	cache.write = func(path string, data []byte) error {
		if err := durableWrite(path, data); err != nil {
			return err
		}
		if path == activePath && failOnce {
			failOnce = false
			return errors.New("injected directory fsync uncertainty after rename")
		}
		return nil
	}
	if _, err := boundary.Apply(next, ApplyOptions{}); err != nil {
		t.Fatalf("apply candidate with post-rename write error: %v", err)
	}
	active, err := cache.Active()
	if err != nil {
		t.Fatalf("read active policy: %v", err)
	}
	if active.Bundle.Version != 2 || liveMode != config.ModeBalanced {
		t.Fatalf("recovered transaction = active v%d live %s, want v2 balanced", active.Bundle.Version, liveMode)
	}
	if consistency != nil {
		t.Fatalf("consistency after durable retry = %v, want nil", consistency)
	}
}

func TestBoundaryApplyDeniesWhenRestoreFails(t *testing.T) {
	key := newTestKey(t)
	cache := openTestCache(t)
	first := signedTestBundle(t, key, "first", 1, "")
	firstHash, err := first.CanonicalHash()
	if err != nil {
		t.Fatalf("hash first policy: %v", err)
	}
	next := signedBoundaryBundle(t, key, "next", 2, firstHash, "mode: balanced\n")
	nextHash, err := next.CanonicalHash()
	if err != nil {
		t.Fatalf("hash next policy: %v", err)
	}
	var consistency error
	boundary := Boundary{
		Cache:        cache,
		Identity:     testIdentity(),
		Resolver:     testResolver(key),
		LocalVersion: "1.2.3",
		Now:          func() time.Time { return testNow },
		Reload: func(cfg *config.Config) error {
			if cfg.Mode == config.ModeBalanced {
				return os.Remove(filepath.Join(cache.configsDir, nextHash+configExt))
			}
			return nil
		},
		Restore:     func() error { return errors.New("injected restore failure") },
		Consistency: func(err error) { consistency = err },
	}
	if _, err := boundary.Apply(first, ApplyOptions{}); err != nil {
		t.Fatalf("apply first policy: %v", err)
	}
	_, err = boundary.Apply(next, ApplyOptions{})
	if !errors.Is(err, ErrLivePolicyUncertain) {
		t.Fatalf("apply candidate error = %v, want ErrLivePolicyUncertain", err)
	}
	if !errors.Is(consistency, ErrLivePolicyUncertain) {
		t.Fatalf("consistency error = %v, want ErrLivePolicyUncertain", consistency)
	}
}

func signedBoundaryBundle(t *testing.T, key testKey, id string, version uint64, previousHash, yaml string) conductor.PolicyBundle {
	t.Helper()
	bundle := signedTestBundle(t, key, id, version, previousHash)
	bundle.Payload.ConfigYAML = yaml
	var err error
	bundle.PayloadSHA256, err = bundle.Payload.PayloadHash()
	if err != nil {
		t.Fatalf("hash payload: %v", err)
	}
	bundle.PolicyHash, err = bundle.Payload.PolicyHash()
	if err != nil {
		t.Fatalf("hash policy: %v", err)
	}
	bundle.Signatures = []conductor.SignatureProof{signProof(t, key, bundle.SignablePreimage)}
	return bundle
}
