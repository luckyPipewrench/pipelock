//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/applycache"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestConductorFollowerLabels_WiresConfigAndCopies proves the helper BOTH apply
// builders use sources cfg.Conductor.Labels (the wiring #744 was missing) and
// returns an independent copy, so the captured applier never shares a map with a
// later-mutated config. nil/empty config returns nil (fail closed).
func TestConductorFollowerLabels_WiresConfigAndCopies(t *testing.T) {
	if got := conductorFollowerLabels(nil); got != nil {
		t.Fatalf("conductorFollowerLabels(nil) = %v, want nil", got)
	}
	if got := conductorFollowerLabels(&config.Config{}); got != nil {
		t.Fatalf("conductorFollowerLabels(empty) = %v, want nil", got)
	}
	cfg := &config.Config{}
	cfg.Conductor.Labels = map[string]string{"ring": "canary"}
	got := conductorFollowerLabels(cfg)
	if got["ring"] != "canary" {
		t.Fatalf("conductorFollowerLabels()[ring] = %q, want canary", got["ring"])
	}
	// Mutating the returned copy must not affect the source config.
	got["ring"] = "mutated"
	if cfg.Conductor.Labels["ring"] != "canary" {
		t.Fatalf("source labels mutated through returned copy: %q", cfg.Conductor.Labels["ring"])
	}
}

// TestBuildConductorRemoteKillApplier_CapturesFollowerLabels proves the
// remote-kill audience path uses the same configured follower labels as policy
// bundle and rollback applies. A label-scoped remote kill would otherwise fail
// closed on every labeled follower because RemoteKillApplier.Labels stayed nil.
func TestBuildConductorRemoteKillApplier_CapturesFollowerLabels(t *testing.T) {
	cfg := config.Defaults()
	cfg.Conductor.OrgID = "org-main"
	cfg.Conductor.FleetID = "prod"
	cfg.Conductor.InstanceID = "pl-prod-1"
	cfg.Conductor.BundleCacheDir = t.TempDir()
	cfg.Conductor.HonorRemoteKillSwitch = true
	cfg.Conductor.Labels = map[string]string{"ring": "canary"}

	applier := buildConductorRemoteKillApplier(cfg, nil, nil, nil)
	if applier.Labels["ring"] != "canary" {
		t.Fatalf("remote kill labels[ring] = %q, want canary", applier.Labels["ring"])
	}
	cfg.Conductor.Labels["ring"] = "stable"
	if applier.Labels["ring"] != "canary" {
		t.Fatalf("remote kill labels aliased config mutation: got %q, want canary", applier.Labels["ring"])
	}
}

// signedLabelScopedBundle mirrors signedRuntimePolicyBundle but targets the
// bundle at an audience LABEL selector instead of an instance ID. The follower's
// configured labels (passed via ConductorApplyOptions.Labels) must match every
// audience label key for the bundle to apply.
func signedLabelScopedBundle(t *testing.T, signer runtimePolicySigner, id string, version uint64, previousHash, configYAML string, audienceLabels map[string]string) conductor.PolicyBundle {
	t.Helper()
	now := time.Now().UTC()
	payload := conductor.PolicyBundlePayload{ConfigYAML: configYAML}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash() error = %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash() error = %v", err)
	}
	bundle := conductor.PolicyBundle{
		SchemaVersion:      conductor.SchemaVersion,
		BundleID:           id,
		OrgID:              "org-main",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           conductor.Audience{Labels: audienceLabels},
		Version:            version,
		PreviousBundleHash: previousHash,
		CreatedAt:          now.Add(-time.Minute),
		NotBefore:          now.Add(-time.Minute),
		ExpiresAt:          now.Add(time.Hour),
		MinPipelockVersion: "0.0.1",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: signer.id,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(signer.priv, preimage)),
	}}
	return bundle
}

// canaryAudience is the audience-label selector both the forward and rollback
// label-filtering tests target.
var canaryAudience = map[string]string{"ring": "canary"}

// TestApplyConductorPolicyBundle_AppliesForMatchingFollowerLabels is the
// consumed-not-inert proof for the FORWARD apply path: a label-scoped bundle
// (audience ring=canary) APPLIES when the follower's labels match and is
// REJECTED (audience mismatch) when they do not. The follower's labels reach the
// apply boundary via ConductorApplyOptions.Labels, which the forward applier
// closure sources from cfg.Conductor.Labels.
func TestApplyConductorPolicyBundle_AppliesForMatchingFollowerLabels(t *testing.T) {
	bundleYAML := strings.Join([]string{
		"mode: strict",
		"api_allowlist:",
		"  - api.example.com",
		"",
	}, "\n")

	t.Run("matching_labels_apply", func(t *testing.T) {
		s, signer := newConductorApplyTestServer(t)
		bundle := signedLabelScopedBundle(t, signer, "labelled-1", 1, "", bundleYAML, canaryAudience)
		applied, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{
			Resolver: signer.resolver(),
			Labels:   map[string]string{"ring": "canary"},
		})
		if err != nil {
			t.Fatalf("ApplyConductorPolicyBundle(matching labels) error = %v, want apply", err)
		}
		if applied.Bundle.BundleID != "labelled-1" {
			t.Fatalf("applied bundle = %q, want labelled-1", applied.Bundle.BundleID)
		}
	})

	t.Run("non_matching_labels_rejected", func(t *testing.T) {
		s, signer := newConductorApplyTestServer(t)
		bundle := signedLabelScopedBundle(t, signer, "labelled-1", 1, "", bundleYAML, canaryAudience)
		_, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{
			Resolver: signer.resolver(),
			Labels:   map[string]string{"ring": "stable"},
		})
		if !errors.Is(err, conductor.ErrAudienceMismatch) {
			t.Fatalf("ApplyConductorPolicyBundle(non-matching labels) error = %v, want ErrAudienceMismatch", err)
		}
	})

	t.Run("nil_labels_rejected", func(t *testing.T) {
		s, signer := newConductorApplyTestServer(t)
		bundle := signedLabelScopedBundle(t, signer, "labelled-1", 1, "", bundleYAML, canaryAudience)
		// nil labels is the pre-fix bug state: a label-scoped bundle could never
		// match because the applier passed empty labels. This asserts the
		// fail-closed default still rejects, so the wiring (not a blanket allow)
		// is what makes the matching case work.
		_, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{
			Resolver: signer.resolver(),
		})
		if !errors.Is(err, conductor.ErrAudienceMismatch) {
			t.Fatalf("ApplyConductorPolicyBundle(nil labels) error = %v, want ErrAudienceMismatch", err)
		}
	})
}

// applyTwoLabelScopedBundles applies a label-scoped bundle-1 then bundle-2 (with
// bundle-1 as base) using the supplied follower labels, returning the cache and
// the two bundles. After this the active bundle is bundle-2 with its on-disk
// BaseHash pointing at bundle-1, so a rollback to bundle-1 is possible.
func applyTwoLabelScopedBundles(t *testing.T, s *Server, policy runtimePolicySigner, followerLabels map[string]string) (*applycache.Cache, conductor.PolicyBundle, conductor.PolicyBundle) {
	t.Helper()
	b1 := signedLabelScopedBundle(t, policy, "bundle-1", 1, "", rollbackTestBundle1YAML, canaryAudience)
	if _, err := s.ApplyConductorPolicyBundle(b1, ConductorApplyOptions{Resolver: policy.resolver(), Labels: followerLabels}); err != nil {
		t.Fatalf("apply label-scoped bundle-1: %v", err)
	}
	b1Hash, err := b1.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(bundle-1): %v", err)
	}
	b2 := signedLabelScopedBundle(t, policy, "bundle-2", 2, b1Hash, rollbackTestBundle2YAML, canaryAudience)
	if _, err := s.ApplyConductorPolicyBundle(b2, ConductorApplyOptions{Resolver: policy.resolver(), Labels: followerLabels}); err != nil {
		t.Fatalf("apply label-scoped bundle-2: %v", err)
	}
	cache, _ := s.conductorApply.(*applycache.Cache)
	if cache == nil {
		t.Fatalf("conductorApply: want *applycache.Cache, got %T", s.conductorApply)
	}
	return cache, b1, b2
}

// TestConductorRollbackApplier_HonorsFollowerLabels is the consumed-not-inert
// proof for the ROLLBACK apply path: a label-scoped rollback target APPLIES when
// the conductorRollbackApplier carries matching follower labels and is REJECTED
// (audience mismatch) when its labels do not match. The labels field is the one
// buildConductorRollbackPoller populates from cfg.Conductor.Labels.
func TestConductorRollbackApplier_HonorsFollowerLabels(t *testing.T) {
	matching := map[string]string{"ring": "canary"}

	t.Run("matching_labels_rollback_applies", func(t *testing.T) {
		s, policy := newConductorApplyTestServer(t)
		cache, b1, b2 := applyTwoLabelScopedBundles(t, s, policy, matching)
		if !liveAllowlistHas(t, s, rollbackBundle2Host) {
			t.Fatalf("pre-rollback live allowlist missing %q (bundle-2)", rollbackBundle2Host)
		}

		rb1 := newRollbackSigner(t, "rollback-1")
		rb2 := newRollbackSigner(t, "rollback-2")
		auth := signedRuntimeRollbackAuth(t, b2, b1, rb1, rb2)

		applier := conductorRollbackApplier{
			server:   s,
			cache:    cache,
			resolver: combinedResolver(policy, rb1, rb2),
			labels:   matching,
		}
		if err := applier.ApplyRollback(auth); err != nil {
			t.Fatalf("ApplyRollback(matching labels) error = %v, want rollback", err)
		}
		active, err := cache.Active()
		if err != nil {
			t.Fatalf("Active() error = %v", err)
		}
		if active.Bundle.BundleID != "bundle-1" {
			t.Fatalf("post-rollback active = %s, want bundle-1", active.Bundle.BundleID)
		}
		if !liveAllowlistHas(t, s, rollbackBundle1Host) {
			t.Fatalf("post-rollback live allowlist missing %q (bundle-1)", rollbackBundle1Host)
		}
	})

	t.Run("non_matching_labels_rollback_rejected", func(t *testing.T) {
		s, policy := newConductorApplyTestServer(t)
		// Bundles are applied with matching labels so they land on disk; the
		// rollback applier then carries NON-matching labels.
		cache, b1, b2 := applyTwoLabelScopedBundles(t, s, policy, matching)

		rb1 := newRollbackSigner(t, "rollback-1")
		rb2 := newRollbackSigner(t, "rollback-2")
		auth := signedRuntimeRollbackAuth(t, b2, b1, rb1, rb2)

		applier := conductorRollbackApplier{
			server:   s,
			cache:    cache,
			resolver: combinedResolver(policy, rb1, rb2),
			labels:   map[string]string{"ring": "stable"},
		}
		if err := applier.ApplyRollback(auth); !errors.Is(err, conductor.ErrAudienceMismatch) {
			t.Fatalf("ApplyRollback(non-matching labels) error = %v, want ErrAudienceMismatch", err)
		}
		active, err := cache.Active()
		if err != nil {
			t.Fatalf("Active() error = %v", err)
		}
		if active.Bundle.BundleID != "bundle-2" {
			t.Fatalf("active after rejected rollback = %s, want bundle-2 (unchanged)", active.Bundle.BundleID)
		}
	})

	t.Run("nil_labels_rollback_rejected", func(t *testing.T) {
		s, policy := newConductorApplyTestServer(t)
		cache, b1, b2 := applyTwoLabelScopedBundles(t, s, policy, matching)

		rb1 := newRollbackSigner(t, "rollback-1")
		rb2 := newRollbackSigner(t, "rollback-2")
		auth := signedRuntimeRollbackAuth(t, b2, b1, rb1, rb2)

		// nil labels is the pre-fix bug state for the rollback path: the
		// conductorRollbackApplier.labels field was never populated, so a
		// label-scoped rollback could never match.
		applier := conductorRollbackApplier{
			server:   s,
			cache:    cache,
			resolver: combinedResolver(policy, rb1, rb2),
		}
		if err := applier.ApplyRollback(auth); !errors.Is(err, conductor.ErrAudienceMismatch) {
			t.Fatalf("ApplyRollback(nil labels) error = %v, want ErrAudienceMismatch", err)
		}
	})
}
