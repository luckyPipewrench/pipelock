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

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBoundaryApplyActivationFailureStates(t *testing.T) {
	for _, tc := range []struct {
		name      string
		first     bool
		uncertain bool
		restores  int
	}{
		{name: "first apply", first: true, restores: 1},
		{name: "first unreadable pointer", first: true, uncertain: true},
		{name: "first incomplete pointer", first: true, uncertain: true},
		{name: "first competing pointer", first: true, uncertain: true},
		{name: "prior pointer preserved", restores: 1},
		{name: "persistent post-rename failure", uncertain: true},
		{name: "unreadable pointer", uncertain: true},
		{name: "removed pointer", uncertain: true},
		{name: "competing pointer", uncertain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := newTestKey(t)
			cache := openTestCache(t)
			priorHash := ""
			if !tc.first {
				prior, err := cache.storeVerified(signedTestBundle(t, key, "prior", 1, ""), testVerifyOptions(key))
				if err != nil {
					t.Fatal(err)
				}
				priorHash = prior.BundleHash
			}
			candidate := signedTestBundle(t, key, "candidate", 2, priorHash)
			activePath := filepath.Join(cache.dir, activeRecordName)
			writeFailure := errors.New("synthetic active-pointer write failure")
			cache.write = func(path string, data []byte) error {
				if path != activePath {
					return durableWrite(path, data)
				}
				if tc.name == "persistent post-rename failure" {
					if err := durableWrite(path, data); err != nil {
						return err
					}
				}
				return writeFailure
			}
			restores := 0
			var consistency error
			boundary := Boundary{
				Cache: cache, Identity: testIdentity(), Resolver: testResolver(key),
				LocalVersion: "1.2.3", Now: func() time.Time { return testNow },
				Reload: func(*config.Config) error {
					switch tc.name {
					case "unreadable pointer", "first unreadable pointer":
						return os.WriteFile(activePath, []byte("invalid record"), 0o600)
					case "first incomplete pointer":
						return os.WriteFile(activePath, []byte("{}"), 0o600)
					case "removed pointer":
						return os.Remove(activePath)
					case "competing pointer", "first competing pointer":
						cache.write = nil
						_, err := cache.storeVerified(signedTestBundle(t, key, "competing", 3, priorHash), testVerifyOptions(key))
						return err
					}
					return nil
				},
				Restore:     func() error { restores++; return nil },
				Consistency: func(err error) { consistency = err },
			}
			_, err := boundary.Apply(candidate, ApplyOptions{})
			if err == nil || errors.Is(err, ErrLivePolicyUncertain) != tc.uncertain {
				t.Fatalf("apply error = %v, want uncertain=%v", err, tc.uncertain)
			}
			if errors.Is(consistency, ErrLivePolicyUncertain) != tc.uncertain || restores != tc.restores {
				t.Fatalf("consistency=%v restores=%d, want uncertain=%v restores=%d", consistency, restores, tc.uncertain, tc.restores)
			}
			active, activeErr := cache.Active()
			switch tc.name {
			case "first apply", "removed pointer":
				if !errors.Is(activeErr, ErrNoValidBundle) {
					t.Fatalf("active error=%v, want missing bundle", activeErr)
				}
			case "unreadable pointer", "first unreadable pointer", "first incomplete pointer":
				if activeErr == nil || errors.Is(activeErr, ErrNoValidBundle) {
					t.Fatal("invalid active pointer was accepted")
				}
			default:
				wantVersion := uint64(1)
				switch tc.name {
				case "persistent post-rename failure":
					wantVersion = 2
				case "competing pointer", "first competing pointer":
					wantVersion = 3
				}
				if activeErr != nil || active.Bundle.Version != wantVersion {
					t.Fatalf("active version=%d error=%v, want %d", active.Bundle.Version, activeErr, wantVersion)
				}
			}
		})
	}
}
