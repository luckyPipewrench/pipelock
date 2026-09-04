// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestBuildImagesBrokerPreflightArgumentsPassCheckConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "fly-playground", "build-images.sh"))
	if err != nil {
		t.Fatalf("read build-images.sh: %v", err)
	}
	const start = "BROKER_PREFLIGHT_ARGS=("
	section := string(raw)
	startAt := strings.Index(section, start)
	if startAt < 0 {
		t.Fatal("build-images.sh has no broker preflight argument array")
	}
	section = section[startAt+len(start):]
	endAt := strings.Index(section, "\n)")
	if endAt < 0 {
		t.Fatal("broker preflight argument array is not terminated")
	}
	args := strings.Fields(section[:endAt])
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("<!doctype html><title>preflight</title>"), 0o600); err != nil {
		t.Fatalf("write preflight UI: %v", err)
	}
	for i, arg := range args {
		if arg == "/srv/ui" {
			args[i] = staticDir
		}
	}

	t.Setenv(envOrchestratorKey, "")
	cmd := newRootCmd()
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("shipped broker preflight rejected by --check-config: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "valid") {
		t.Fatalf("preflight output = %q, want validity statement", out.String())
	}
}

func TestBuildImagesOnlyVMDoesNotRequireViewer(t *testing.T) {
	tmp := t.TempDir()
	dockerLog := filepath.Join(tmp, "docker.log")
	dockerPath := filepath.Join(tmp, "docker")
	dockerStub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$DOCKER_LOG\"\n"
	if err := os.WriteFile(dockerPath, []byte(dockerStub), 0o600); err != nil {
		t.Fatalf("write docker stub: %v", err)
	}
	// The temporary file has to be executable because build-images.sh resolves
	// docker through PATH. It contains only the fixed test stub above.
	if err := os.Chmod(dockerPath, 0o700); err != nil { // #nosec G302 -- executable test stub
		t.Fatalf("make docker stub executable: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "bash", "../../deploy/fly-playground/build-images.sh", "--only", "vm")
	cmd.Env = append(os.Environ(),
		"PATH="+tmp+":"+os.Getenv("PATH"),
		"DOCKER_LOG="+dockerLog,
		"PLAYGROUND_REGISTRY=registry.example/playground",
		"PLAYGROUND_UI_DIR=",
		"PLAYGROUND_PUSH=",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("VM-only build failed: %v\n%s", err, output)
	}
	logBytes, err := os.ReadFile(filepath.Clean(dockerLog))
	if err != nil {
		t.Fatalf("read docker log: %v", err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "Dockerfile") || strings.Contains(logText, "Dockerfile.broker") || strings.Contains(logText, " run ") {
		t.Fatalf("VM-only docker calls = %q", logText)
	}
}

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

func TestRunServePrintRequiredEnvReportsNamesWithoutReadingValues(t *testing.T) {
	f := testServeFlags(t, 0)
	f.printRequiredEnv = true
	f.requireSessionSecrets = true
	f.flyTokenFile = ""
	f.flyTokenEnv = "BROKER_FLY_TOKEN"
	f.turnstileSecretEnv = "BROKER_TURNSTILE_SECRET"
	f.unsafeNoHumanGate = false
	f.turnstileSitekey = "site-key"
	f.turnstileExpectedHostname = "playground.example"
	f.turnstileExpectedAction = "playground-session"
	f.image = "registry.example/playground@sha256:" + strings.Repeat("a", 64)
	f.vmImageDigest = "sha256:" + strings.Repeat("a", 64)
	t.Setenv("BROKER_FLY_TOKEN", "must-not-be-read-or-printed")

	cmd := newServeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runServe(cmd, f); err != nil {
		t.Fatalf("print required env: %v", err)
	}
	got := strings.Fields(out.String())
	want := []string{"BROKER_FLY_TOKEN", "BROKER_TURNSTILE_SECRET", envModelKey, envOrchestratorRoot}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("required env = %q, want %q", got, want)
	}
	if strings.Contains(out.String(), "must-not-be-read-or-printed") {
		t.Fatal("required-env report exposed an environment value")
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
