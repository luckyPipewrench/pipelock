// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

// A malformed root must fail closed. Serving with an unusable signing root
// would mint delegations nothing can verify.
func TestResolveOrchestratorRoot_MalformedFailsClosed(t *testing.T) {
	t.Setenv(envOrchestratorRoot, "not-hex-at-all")
	if _, err := resolveOrchestratorRoot(&serveFlags{requireSessionSecrets: true}); err == nil {
		t.Fatal("a malformed orchestrator root must fail closed")
	}
}

// The digest is what binds a delegation to one immutable image, so a value
// that merely looks digest-shaped must be refused.
func TestResolveImageDigest_RejectsNonCanonical(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest string
	}{
		{name: "non_hex_characters", digest: "sha256:" + strings.Repeat("z", 64)},
		{name: "wrong_algorithm", digest: "sha512:" + strings.Repeat("a", 64)},
		{name: "too_long", digest: "sha256:" + strings.Repeat("a", 65)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveImageDigest(&serveFlags{vmImageDigest: tc.digest, requireSessionSecrets: true}); err == nil {
				t.Fatalf("digest %q must be refused", tc.digest)
			}
		})
	}
}

// The broker refuses to serve while the guest-facing signing variable is set.
// Broker and visitor VMs share app-level secrets, so a value under that name
// reaches every guest and silently turns delegation off.
func TestBuildServer_RefusesGuestFacingRootSecret(t *testing.T) {
	f := testServeFlags(t, 0)
	f.vmImageDigest = "sha256:" + strings.Repeat("a", 64)
	t.Setenv(envOrchestratorKey, "deadbeef")
	_, _, _, _, err := buildServer(context.Background(), io.Discard, f)
	if err == nil {
		t.Fatal("buildServer must refuse while the guest-facing root secret is set")
	}
	if !strings.Contains(err.Error(), envOrchestratorRoot) {
		t.Fatalf("error %v must point the operator at %s", err, envOrchestratorRoot)
	}
}
