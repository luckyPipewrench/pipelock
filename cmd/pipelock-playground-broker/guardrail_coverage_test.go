// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// A malformed root must fail closed. Serving with an unusable signing root
// would mint delegations nothing can verify.
func TestResolveOrchestratorRoot_MalformedFailsClosed(t *testing.T) {
	t.Setenv(envOrchestratorRoot, "not-hex-at-all")
	if _, err := resolveOrchestratorRoot(&serveFlags{requireSessionSecrets: true}); err == nil {
		t.Fatal("a malformed orchestrator root must fail closed")
	}
}

// Production derives delegated-signing enforcement from the existing session
// secret policy. An absent root must name the default deployment variable so
// the operator can repair the startup refusal directly.
func TestResolveOrchestratorRoot_MissingProductionRootNamesEnvironment(t *testing.T) {
	t.Setenv(envOrchestratorRoot, "")
	_, err := resolveOrchestratorRoot(&serveFlags{requireSessionSecrets: true})
	if err == nil {
		t.Fatal("an absent production orchestrator root must fail closed")
	}
	if !strings.Contains(err.Error(), envOrchestratorRoot) {
		t.Fatalf("error %v must name %s", err, envOrchestratorRoot)
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

// The check-config path resolves flags without touching secrets or a provider,
// so it must still refuse a broker environment that would leak the root to
// guests. An operator validating a config needs that answer before deploying.
func TestRunServeCheckConfig_RefusesGuestFacingRootSecret(t *testing.T) {
	f := testServeFlags(t, 0)
	f.checkConfig = true
	f.vmImageDigest = "sha256:" + strings.Repeat("a", 64)
	t.Setenv(envOrchestratorKey, "deadbeef")

	cmd := newServeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runServe(cmd, f)
	if err == nil {
		t.Fatal("check-config must refuse while the guest-facing root secret is set")
	}
	if !strings.Contains(err.Error(), envOrchestratorRoot) {
		t.Fatalf("error %v must point the operator at %s", err, envOrchestratorRoot)
	}
}

// With a clean environment the same path reports the config valid, so the
// refusal above is the guard firing rather than an unrelated failure.
func TestRunServeCheckConfig_PassesWithCleanEnvironment(t *testing.T) {
	f := testServeFlags(t, 0)
	f.checkConfig = true
	f.vmImageDigest = "sha256:" + strings.Repeat("a", 64)
	t.Setenv(envOrchestratorKey, "")

	cmd := newServeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runServe(cmd, f); err != nil {
		t.Fatalf("clean check-config rejected: %v", err)
	}
	if !strings.Contains(out.String(), "valid") {
		t.Fatalf("check-config output = %q, want a validity statement", out.String())
	}
}

// An unreadable root file fails closed at resolution. Starting without a usable
// root would mint nothing, and every session would then run unsigned.
func TestResolveOrchestratorRoot_UnreadableFileFailsClosed(t *testing.T) {
	f := &serveFlags{
		orchestratorKeyFile:   filepath.Join(t.TempDir(), "absent-root.key"),
		requireSessionSecrets: true,
	}
	if _, err := resolveOrchestratorRoot(f); err == nil {
		t.Fatal("an unreadable orchestrator root must fail closed")
	}
}

// A malformed digest must stop check-config, not merely be reported later. An
// operator validating a config before deploying needs the refusal then.
func TestRunServeCheckConfig_RefusesMalformedImageDigest(t *testing.T) {
	f := testServeFlags(t, 0)
	f.checkConfig = true
	f.vmImageDigest = "sha256:not-a-digest"

	cmd := newServeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runServe(cmd, f); err == nil {
		t.Fatal("check-config must refuse a malformed image digest")
	}
}

// Server construction refuses a root that is not the published identity, and a
// digest that is not canonical, before anything starts serving.
func TestBuildServer_RefusesUnusableSigningInputs(t *testing.T) {
	t.Run("root_is_not_the_published_identity", func(t *testing.T) {
		_, priv, err := signing.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		oldFactory := newMachineProvider
		newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
			return fakeProvider{}, nil
		}
		t.Cleanup(func() { newMachineProvider = oldFactory })

		f := testServeFlags(t, 0)
		f.orchestratorKeyFile = writeTestFile(t, t.TempDir(), "orch.key", hex.EncodeToString(priv)+"\n")
		_, _, _, _, err = buildServer(context.Background(), io.Discard, f)
		if err == nil {
			t.Fatal("a root that is not the published identity must be refused")
		}
		if !strings.Contains(err.Error(), "published orchestrator identity") {
			t.Fatalf("error %v must name the published identity", err)
		}
	})

	t.Run("digest_is_not_canonical", func(t *testing.T) {
		f := testServeFlags(t, 0)
		f.vmImageDigest = "sha256:not-a-digest"
		_, _, _, _, err := buildServer(context.Background(), io.Discard, f)
		if err == nil {
			t.Fatal("a malformed image digest must be refused")
		}
	})
}
