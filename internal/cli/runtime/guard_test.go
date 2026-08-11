// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	guardfs "github.com/luckyPipewrench/pipelock/internal/guard"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestLaunchGuardBuildsEnforcedStandaloneLaunch(t *testing.T) {
	workspace := t.TempDir()
	cfg := config.Defaults()
	var got sandbox.StandaloneLaunchConfig
	err := launchGuard(GuardLaunchOptions{
		Context:   t.Context(),
		Config:    cfg,
		Workspace: workspace,
		Command:   []string{"/usr/bin/true"},
		Stderr:    io.Discard,
	}, func(launch sandbox.StandaloneLaunchConfig) error {
		got = launch
		return nil
	})
	if err != nil {
		t.Fatalf("launchGuard: %v", err)
	}
	if !got.RequireNetNS || !got.RequireProxyHandler || !got.UseDeveloperEnvironment {
		t.Fatalf("launch requirements = %+v", got)
	}
	wantRuntimeConfig := cfg.Clone()
	wantRuntimeConfig.ForwardProxy.Enabled = true
	if got.GuardDeclaration == nil || got.GuardPolicyHash != wantRuntimeConfig.CanonicalPolicyHash() {
		t.Fatalf("guard binding declaration=%v hash=%q", got.GuardDeclaration, got.GuardPolicyHash)
	}
	if got.ProxyHandler == nil || got.Policy == nil {
		t.Fatalf("launch omitted proxy or policy: %+v", got)
	}
}

func TestLaunchGuardRejectsInvalidRequestsBeforeLaunch(t *testing.T) {
	workspace := t.TempDir()
	profileCfg := config.Defaults()
	profileCfg.Guard.Profiles = []config.GuardProfile{{Name: "worker"}}
	for _, testCase := range []struct {
		name    string
		opts    GuardLaunchOptions
		wantErr string
	}{
		{name: "nil config", opts: GuardLaunchOptions{Workspace: workspace, Command: []string{"true"}}, wantErr: "config is nil"},
		{name: "empty command", opts: GuardLaunchOptions{Config: config.Defaults(), Workspace: workspace}, wantErr: "command is empty"},
		{name: "invalid workspace", opts: GuardLaunchOptions{Config: config.Defaults(), Workspace: filepath.Join(workspace, "missing"), Command: []string{"true"}}, wantErr: "workspace"},
		{name: "missing executable", opts: GuardLaunchOptions{Config: config.Defaults(), Workspace: workspace, Command: []string{"missing-guard-command"}}, wantErr: "resolving guard command"},
		{name: "missing profile", opts: GuardLaunchOptions{Config: profileCfg, Profile: "missing", Workspace: workspace, Command: []string{"true"}}, wantErr: "profile"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			called := false
			err := launchGuard(testCase.opts, func(sandbox.StandaloneLaunchConfig) error {
				called = true
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want %q", err, testCase.wantErr)
			}
			if called {
				t.Fatal("invalid request reached sandbox launch")
			}
		})
	}
}

func TestLaunchGuardReturnsSandboxFailure(t *testing.T) {
	sentinel := errors.New("sandbox refused")
	err := launchGuard(GuardLaunchOptions{
		Config: config.Defaults(), Workspace: t.TempDir(), Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
	}, func(sandbox.StandaloneLaunchConfig) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want sandbox failure", err)
	}
}

func TestValidateGuardRuntimeFailsClosed(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "best effort",
			mutate: func(cfg *config.Config) {
				cfg.Sandbox.BestEffort = true
			},
			wantErr: "best_effort:true",
		},
		{
			name: "audit only",
			mutate: func(cfg *config.Config) {
				enforce := false
				cfg.Enforce = &enforce
			},
			wantErr: "enforce:false",
		},
		{
			name: "environment scan disabled",
			mutate: func(cfg *config.Config) {
				cfg.DLP.ScanEnv = false
			},
			wantErr: "scan_env:false",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.Defaults()
			testCase.mutate(cfg)
			if err := validateGuardRuntime(cfg); err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want %q", err, testCase.wantErr)
			}
		})
	}
}

func TestGuardDestinationGrantsAreExact(t *testing.T) {
	grants, err := guardDestinationGrants([]config.GuardService{{
		Name: "vendor API", Protocol: "tcp", Host: "API.Vendor.Example.", Port: 443,
	}})
	if err != nil {
		t.Fatalf("guardDestinationGrants: %v", err)
	}
	exact, err := destination.New(destination.NetworkTCP, "api.vendor.example", 443)
	if err != nil {
		t.Fatalf("exact destination: %v", err)
	}
	if decision := grants.Evaluate(exact); decision.Effect != destination.EffectAllow {
		t.Fatalf("exact decision = %+v, want allow", decision)
	}
	siblingPort, err := destination.New(destination.NetworkTCP, "api.vendor.example", 444)
	if err != nil {
		t.Fatalf("sibling destination: %v", err)
	}
	if decision := grants.Evaluate(siblingPort); decision.Effect != destination.EffectNoMatch {
		t.Fatalf("sibling-port decision = %+v, want no match", decision)
	}
}

func TestGuardSandboxPolicyRequiresProfileAndMergesSelectedManifest(t *testing.T) {
	workspace := t.TempDir()
	state := t.TempDir()
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles: []config.GuardProfile{{Name: "worker", Manifests: []string{"state"}}},
		Manifests: []config.GuardManifest{{
			Name: "state", ReadWriteDirectories: []string{state},
		}},
	}
	if _, err := guardSandboxPolicy(cfg, "", workspace); err == nil || !strings.Contains(err.Error(), "profile is required") {
		t.Fatalf("missing profile error = %v", err)
	}
	policy, err := guardSandboxPolicy(cfg, "worker", workspace)
	if err != nil {
		t.Fatalf("guardSandboxPolicy: %v", err)
	}
	if !containsString(policy.AllowRWDirs, state) {
		t.Fatalf("RW dirs = %v, want selected state %q", policy.AllowRWDirs, state)
	}
}

func TestValidateGuardRuntimeObjectsRejectsSocketGrant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket fixture is unavailable on Windows")
	}
	socketDir, err := os.MkdirTemp("/tmp", "plk-guard-sock-")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "agent.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "worker", Manifests: []string{"state"}}},
		Manifests: []config.GuardManifest{{Name: "state", ReadWrite: []string{socketPath}}},
	}
	if err := validateGuardRuntimeObjects(cfg, "worker"); err == nil || !strings.Contains(err.Error(), "sockets") {
		t.Fatalf("socket grant error = %v", err)
	}
}

func TestValidateGuardRuntimeObjectsRejectsWrongAndMissingPathTypes(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	missingParent := filepath.Join(root, "missing", "state")
	fileParent := filepath.Join(file, "state")
	for _, testCase := range []struct {
		name     string
		manifest config.GuardManifest
		wantErr  string
	}{
		{name: "missing read file", manifest: config.GuardManifest{Name: "m", ReadOnly: []string{filepath.Join(root, "missing")}}, wantErr: "does not exist"},
		{name: "file used as directory", manifest: config.GuardManifest{Name: "m", ReadOnlyDirectories: []string{file}}, wantErr: "not a directory"},
		{name: "directory used as file", manifest: config.GuardManifest{Name: "m", ReadOnly: []string{root}}, wantErr: "not a regular file"},
		{name: "missing writable parent", manifest: config.GuardManifest{Name: "m", ReadWriteDirectories: []string{missingParent}}, wantErr: "parent"},
		{name: "writable parent is file", manifest: config.GuardManifest{Name: "m", ReadWriteDirectories: []string{fileParent}}, wantErr: "not a directory"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Guard = config.Guard{
				Profiles:  []config.GuardProfile{{Name: "worker", Manifests: []string{"m"}}},
				Manifests: []config.GuardManifest{testCase.manifest},
			}
			err := validateGuardRuntimeObjects(cfg, "worker")
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want %q", err, testCase.wantErr)
			}
		})
	}

	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles: []config.GuardProfile{{Name: "worker", Manifests: []string{"selected"}}},
		Manifests: []config.GuardManifest{
			{Name: "selected", ReadOnlyDirectories: []string{root}},
			{Name: "unselected", ReadOnly: []string{filepath.Join(root, "missing")}},
		},
	}
	if err := validateGuardRuntimeObjects(cfg, "worker"); err != nil {
		t.Fatalf("unselected manifest affected runtime validation: %v", err)
	}
}

func TestGuardHelpersCoverAbsentAndInvalidInputs(t *testing.T) {
	cfg := config.Defaults()
	cfg.Guard.Profiles = []config.GuardProfile{{Name: "worker"}}
	if _, err := guardSandboxPolicy(cfg, "missing", t.TempDir()); err == nil {
		t.Fatal("missing profile was accepted by policy builder")
	}
	if err := validateGuardRuntimeObjects(cfg, "missing"); err == nil {
		t.Fatal("missing profile was accepted by object validator")
	}
	if err := validateGuardRuntimeObjects(cfg, ""); err == nil {
		t.Fatal("empty profile was accepted with declared profiles")
	}
	if _, err := resolveGuardExecutable(nil, t.TempDir()); err == nil {
		t.Fatal("empty command was accepted")
	}
	if got := ctxOrBackground(t.Context()); got != t.Context() {
		t.Fatal("non-nil context was replaced")
	}
	var absentContext context.Context
	if ctxOrBackground(absentContext) == nil {
		t.Fatal("nil context was not replaced")
	}
	var nilEvidence *guardEvidence
	nilEvidence.close()

	existing := t.TempDir()
	missing := filepath.Join(existing, "missing")
	got := existingGuardPreflightDirs([]string{existing, missing})
	if len(got) != 1 || got[0] != existing {
		t.Fatalf("existing preflight directories = %v", got)
	}

	var stderr bytes.Buffer
	cfg = config.Defaults()
	cfg.FlightRecorder.Enabled = true
	evidence, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), &stderr)
	if err != nil {
		t.Fatalf("newGuardEvidence inert recorder: %v", err)
	}
	evidence.close()
	if !strings.Contains(stderr.String(), "enabled but inert") {
		t.Fatalf("inert recorder warning missing: %q", stderr.String())
	}
	cfg.FlightRecorder.RequireReceipts = true
	if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil {
		t.Fatal("required receipts without recorder directory were accepted")
	}

	cfg = config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "receipts")
	cfg.FlightRecorder.Redact = false
	cfg.FlightRecorder.SignCheckpoints = false
	stderr.Reset()
	evidence, err = newGuardEvidence(t.Context(), cfg, nil, metrics.New(), &stderr)
	if err != nil {
		t.Fatalf("unsigned recorder: %v", err)
	}
	evidence.close()
	if !strings.Contains(stderr.String(), "Receipts: disabled") {
		t.Fatalf("unsigned receipt warning missing: %q", stderr.String())
	}

	badRecorderDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badRecorderDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write recorder obstruction: %v", err)
	}
	cfg.FlightRecorder.Dir = badRecorderDir
	if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "creating Guard flight recorder") {
		t.Fatalf("recorder creation error = %v", err)
	}

	cfg = config.Defaults()
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "required-receipts")
	cfg.FlightRecorder.Redact = false
	cfg.FlightRecorder.SignCheckpoints = false
	cfg.FlightRecorder.RequireReceipts = true
	if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "no healthy signed Guard receipt emitter") {
		t.Fatalf("required unsigned receipt error = %v", err)
	}

	_, privateKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(privateKey, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "posture-error")
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.SignCheckpoints = true
	t.Setenv("PIPELOCK_POSTURE_PROOF", "relative-proof.json")
	if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "loading Guard posture binding") {
		t.Fatalf("posture binding error = %v", err)
	}

	if _, err := guardDestinationGrants([]config.GuardService{{Name: "bad", Protocol: "bad", Host: "api.vendor.example", Port: 443}}); err == nil {
		t.Fatal("invalid Guard destination was accepted")
	}
}

func TestGuardFirstRunDirectoryIsPreparedBeforeOuterPolicyResolution(t *testing.T) {
	workspace := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "worker", Manifests: []string{"state"}}},
		Manifests: []config.GuardManifest{{Name: "state", ReadWriteDirectories: []string{state}}},
	}
	prepared, err := guardfs.PrepareExecution(cfg, "worker", workspace, workspace, "", os.Getuid())
	if err != nil {
		t.Fatalf("PrepareExecution: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	if !prepared.Complete() {
		t.Fatalf("prepared outcomes = %+v", prepared.Outcomes())
	}
	policy, err := guardSandboxPolicy(cfg, "worker", workspace)
	if err != nil {
		t.Fatalf("guardSandboxPolicy: %v", err)
	}
	if _, err := sandbox.ResolvePolicyPaths(policy); err != nil {
		t.Fatalf("outer policy could not resolve prepared state directory: %v", err)
	}
}

func TestGuardPreflightRefusesWorkspaceThatBypassesWriteFloor(t *testing.T) {
	_, err := GuardPreflight(config.Defaults(), "", "/usr/local/bin", []string{"/usr/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("dangerous workspace preflight error = %v, want compiled-floor refusal", err)
	}
}

func TestGuardPreflightValidatesAndDeclaresEveryRequirement(t *testing.T) {
	if _, err := GuardPreflight(nil, "", t.TempDir(), []string{"/usr/bin/true"}); err == nil {
		t.Fatal("nil preflight config was accepted")
	}
	workspace := t.TempDir()
	result, err := GuardPreflight(config.Defaults(), "", workspace, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatalf("GuardPreflight: %v", err)
	}
	if result.Requirements == nil || !result.Requirements.RequireNetNS || !result.Requirements.RequireProxyHandler || !result.Requirements.RequireLandlock {
		t.Fatalf("preflight requirements = %+v", result.Requirements)
	}
	if _, err := GuardPreflight(config.Defaults(), "", workspace, []string{"missing-guard-command"}); err == nil {
		t.Fatal("missing preflight executable was accepted")
	}
	profileCfg := config.Defaults()
	profileCfg.Guard.Profiles = []config.GuardProfile{{Name: "worker"}}
	if _, err := GuardPreflight(profileCfg, "missing", workspace, []string{"/usr/bin/true"}); err == nil {
		t.Fatal("missing preflight profile was accepted")
	}
}

func TestLaunchGuardPropagatesRuntimeAndEvidenceFailures(t *testing.T) {
	workspace := t.TempDir()
	logDirectory := t.TempDir()
	for _, testCase := range []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{name: "best effort", mutate: func(cfg *config.Config) { cfg.Sandbox.BestEffort = true }, want: "best_effort"},
		{name: "receipts without directory", mutate: func(cfg *config.Config) {
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.RequireReceipts = true
		}, want: "no configured recorder directory"},
		{name: "invalid signing key", mutate: func(cfg *config.Config) {
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "receipts")
			cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "missing.key")
		}, want: "loading Guard receipt signing key"},
		{name: "audit file is directory", mutate: func(cfg *config.Config) {
			cfg.Logging.Output = config.OutputFile
			cfg.Logging.File = logDirectory
		}, want: "create guard audit logger"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.Defaults()
			testCase.mutate(cfg)
			err := launchGuard(GuardLaunchOptions{
				Config: cfg, Workspace: workspace, Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
			}, func(sandbox.StandaloneLaunchConfig) error {
				t.Fatal("failed Guard launch reached sandbox")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
		})
	}

	if err := launchGuard(GuardLaunchOptions{
		Config: config.Defaults(), Workspace: "/usr/local/bin", Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
	}, func(sandbox.StandaloneLaunchConfig) error { return nil }); err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("compiled-floor launch error = %v", err)
	}
}

func TestGuardEvidenceBindsCanonicalPolicyHash(t *testing.T) {
	cfg := config.Defaults()
	recorderDir := filepath.Join(t.TempDir(), "recorder")
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	_, privateKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := signing.SavePrivateKey(privateKey, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = recorderDir
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.RequireReceipts = true
	cfg.Guard.Services = []config.GuardService{{Name: "vendor", Protocol: "tcp", Host: "api.vendor.example", Port: 443}}

	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New: %v", err)
	}
	defer sc.Close()
	evidence, err := newGuardEvidence(context.Background(), cfg, sc, metrics.New(), io.Discard)
	if err != nil {
		t.Fatalf("newGuardEvidence: %v", err)
	}
	evidence.close()

	wantHash := cfg.CanonicalPolicyHash()
	found := false
	recorderRoot, err := os.OpenRoot(recorderDir)
	if err != nil {
		t.Fatalf("open recorder root: %v", err)
	}
	defer func() { _ = recorderRoot.Close() }()
	err = filepath.WalkDir(recorderDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, relErr := filepath.Rel(recorderDir, path)
		if relErr != nil {
			return relErr
		}
		contents, readErr := recorderRoot.ReadFile(relative)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(contents), wantHash) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk recorder: %v", err)
	}
	if !found {
		t.Fatalf("recorder does not contain canonical Guard policy hash %s", wantHash)
	}
}
