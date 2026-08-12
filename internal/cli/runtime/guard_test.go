// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	if got.GuardAppliedPreExec == nil {
		t.Fatal("launch omitted child enforcement callback")
	}
	proof := guardfs.NewExecutionProof(
		guardfs.EnforcementRecord{State: guardfs.EnforcementEnforced, Mechanism: "landlock", Coverage: guardfs.CoverageFull},
		guardfs.ExecControlOptions{PolicyHash: got.GuardPolicyHash, Workspace: workspace, TempDir: workspace, Binary: "/usr/bin/true"},
		[]string{"/usr/bin/true"},
	)
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := got.GuardAppliedPreExec(workspace, encoded); err != nil {
		t.Fatalf("GuardAppliedPreExec: %v", err)
	}
	if err := got.GuardAppliedPreExec(workspace, encoded); err != nil {
		t.Fatalf("repeated GuardAppliedPreExec: %v", err)
	}
	server, client := net.Pipe()
	if err := client.Close(); err != nil {
		t.Fatalf("close proxy client: %v", err)
	}
	got.ProxyHandler(server)
}

func TestLaunchGuardRejectsMalformedChildProof(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var got sandbox.StandaloneLaunchConfig
	err := launchGuard(GuardLaunchOptions{
		Context: ctx, Config: config.Defaults(), Workspace: t.TempDir(),
		Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
	}, func(launch sandbox.StandaloneLaunchConfig) error {
		got = launch
		return nil
	})
	if err != nil {
		t.Fatalf("launchGuard: %v", err)
	}
	if err := got.GuardAppliedPreExec(got.Workspace, []byte("not-json")); err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Fatalf("malformed proof error = %v", err)
	}
	proof := guardfs.NewExecutionProof(
		guardfs.EnforcementRecord{State: guardfs.EnforcementEnforced, Mechanism: "landlock", Coverage: guardfs.CoverageFull},
		guardfs.ExecControlOptions{PolicyHash: "wrong-config", Workspace: "/workspace", TempDir: "/tmp/private", Binary: "/usr/bin/true"},
		[]string{"/usr/bin/true"},
	)
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal mismatched proof: %v", err)
	}
	if err := got.GuardAppliedPreExec(got.Workspace, encoded); err == nil || !strings.Contains(err.Error(), "does not describe") {
		t.Fatalf("mismatched proof error = %v", err)
	}
	tampered := guardfs.NewExecutionProof(
		guardfs.EnforcementRecord{State: guardfs.EnforcementEnforced, Mechanism: "landlock", Coverage: guardfs.CoverageFull},
		guardfs.ExecControlOptions{PolicyHash: got.GuardPolicyHash, Workspace: got.Workspace, TempDir: got.Workspace, Binary: "/usr/bin/true"},
		[]string{"/usr/bin/true"},
	)
	tampered.Record.Coverage = guardfs.CoveragePartial
	encodedTampered, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("marshal tampered proof: %v", err)
	}
	if err := got.GuardAppliedPreExec(got.Workspace, encodedTampered); err == nil {
		t.Fatal("parent evidence boundary accepted a tampered enforcement record")
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*guardfs.ExecutionProof)
	}{
		{name: "profile", mutate: func(proof *guardfs.ExecutionProof) { proof.Profile = "other" }},
		{name: "workspace", mutate: func(proof *guardfs.ExecutionProof) { proof.Workspace = "/other" }},
		{name: "temporary directory", mutate: func(proof *guardfs.ExecutionProof) { proof.TempDir = "/other" }},
		{name: "binary", mutate: func(proof *guardfs.ExecutionProof) { proof.Binary = "/usr/bin/false" }},
		{name: "argv", mutate: func(proof *guardfs.ExecutionProof) { proof.Command = []string{"/usr/bin/false"} }},
	} {
		t.Run("self-consistent wrong "+testCase.name, func(t *testing.T) {
			wrong := guardfs.NewExecutionProof(
				guardfs.EnforcementRecord{State: guardfs.EnforcementEnforced, Mechanism: "landlock", Coverage: guardfs.CoverageFull},
				guardfs.ExecControlOptions{PolicyHash: got.GuardPolicyHash, Workspace: got.Workspace, TempDir: got.Workspace, Binary: "/usr/bin/true"},
				[]string{"/usr/bin/true"},
			)
			testCase.mutate(&wrong)
			// Rebuild after mutation so the digest is valid for the wrong
			// invocation. The parent comparison, not hash mismatch, must deny it.
			wrong = guardfs.NewExecutionProof(wrong.Record, guardfs.ExecControlOptions{
				Profile: wrong.Profile, PolicyHash: wrong.ConfigPolicyHash,
				Workspace: wrong.Workspace, TempDir: wrong.TempDir, Binary: wrong.Binary,
			}, wrong.Command)
			encodedWrong, marshalErr := json.Marshal(wrong)
			if marshalErr != nil {
				t.Fatalf("marshal wrong proof: %v", marshalErr)
			}
			if err := got.GuardAppliedPreExec(got.Workspace, encodedWrong); err == nil || !strings.Contains(err.Error(), "requested invocation") {
				t.Fatalf("wrong invocation proof error = %v", err)
			}
		})
	}
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	done := make(chan struct{})
	go func() {
		got.ProxyHandler(server)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handler did not return after cancellation")
	}
}

func TestGuardWorkspaceResolutionFailsFromRemovedDirectory(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original directory: %v", err)
	}
	removed := t.TempDir()
	if err := os.Chdir(removed); err != nil {
		t.Fatalf("enter removable directory: %v", err)
	}
	defer func() {
		if err := os.Chdir(original); err != nil {
			t.Fatalf("restore original directory: %v", err)
		}
	}()
	if err := os.Remove(removed); err != nil {
		t.Fatalf("remove current directory: %v", err)
	}
	if _, err := GuardPreflight(config.Defaults(), "", "relative", []string{"/usr/bin/true"}); err == nil || !strings.Contains(err.Error(), "resolving guard workspace") {
		t.Fatalf("GuardPreflight error = %v", err)
	}
	if err := launchGuard(GuardLaunchOptions{
		Config: config.Defaults(), Workspace: "relative", Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
	}, func(sandbox.StandaloneLaunchConfig) error { return nil }); err == nil || !strings.Contains(err.Error(), "resolving guard workspace") {
		t.Fatalf("launchGuard error = %v", err)
	}
}

func TestLaunchGuardRejectsInvalidRequestsBeforeLaunch(t *testing.T) {
	if err := LaunchGuard(GuardLaunchOptions{}); err == nil || !strings.Contains(err.Error(), "config is nil") {
		t.Fatalf("LaunchGuard nil-config error = %v", err)
	}
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

func TestLaunchGuardFailureDoesNotEmitEnforcementEvidence(t *testing.T) {
	cfg := config.Defaults()
	recorderDir := filepath.Join(t.TempDir(), "recorder")
	_, privateKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(privateKey, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	cfg.FlightRecorder.Enabled = true
	cfg.FlightRecorder.Dir = recorderDir
	cfg.FlightRecorder.SigningKeyPath = keyPath
	cfg.FlightRecorder.RequireReceipts = true
	sentinel := errors.New("sandbox refused")
	err = launchGuard(GuardLaunchOptions{
		Config: cfg, Workspace: t.TempDir(), Command: []string{"/usr/bin/true"}, Stderr: io.Discard,
	}, func(sandbox.StandaloneLaunchConfig) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("launchGuard error = %v", err)
	}
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
		if strings.Contains(string(contents), "session_open") || strings.Contains(string(contents), "landlock_applied_pre_exec") {
			t.Fatalf("failed launch emitted enforcement evidence in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk recorder: %v", err)
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
	for _, testCase := range []struct {
		name     string
		manifest config.GuardManifest
		wantErr  string
	}{
		{name: "missing read file", manifest: config.GuardManifest{Name: "m", ReadOnly: []string{filepath.Join(root, "missing")}}, wantErr: "does not exist"},
		{name: "missing writable file", manifest: config.GuardManifest{Name: "m", ReadWrite: []string{filepath.Join(root, "missing-writable")}}, wantErr: "does not exist"},
		{name: "file used as directory", manifest: config.GuardManifest{Name: "m", ReadOnlyDirectories: []string{file}}, wantErr: "not a directory"},
		{name: "directory used as file", manifest: config.GuardManifest{Name: "m", ReadOnly: []string{root}}, wantErr: "not a regular file"},
		{name: "missing writable parent", manifest: config.GuardManifest{Name: "m", ReadWriteDirectories: []string{missingParent}}, wantErr: "parent"},
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
	t.Run("profile validation", func(t *testing.T) {
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
	})
	t.Run("empty command", func(t *testing.T) {
		if _, err := resolveGuardExecutable(nil, t.TempDir()); err == nil {
			t.Fatal("empty command was accepted")
		}
	})
	t.Run("context fallback", func(t *testing.T) {
		if got := ctxOrBackground(t.Context()); got != t.Context() {
			t.Fatal("non-nil context was replaced")
		}
		var absentContext context.Context
		if ctxOrBackground(absentContext) == nil {
			t.Fatal("nil context was not replaced")
		}
	})
	t.Run("nil evidence close", func(t *testing.T) {
		var nilEvidence *guardEvidence
		nilEvidence.close()
	})
	t.Run("existing preflight directories", func(t *testing.T) {
		existing := t.TempDir()
		got := existingGuardPreflightDirs([]string{existing, filepath.Join(existing, "missing")})
		if len(got) != 1 || got[0] != existing {
			t.Fatalf("existing preflight directories = %v", got)
		}
	})
	t.Run("inert recorder", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		var stderr bytes.Buffer
		evidence, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), &stderr)
		if err != nil {
			t.Fatalf("newGuardEvidence: %v", err)
		}
		evidence.close()
		if !strings.Contains(stderr.String(), "enabled but inert") {
			t.Fatalf("warning missing: %q", stderr.String())
		}
	})
	t.Run("required receipts need directory", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.RequireReceipts = true
		if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil {
			t.Fatal("required receipts without recorder directory were accepted")
		}
	})
	t.Run("unsigned recorder", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "receipts")
		cfg.FlightRecorder.Redact = false
		cfg.FlightRecorder.SignCheckpoints = false
		var stderr bytes.Buffer
		evidence, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), &stderr)
		if err != nil {
			t.Fatalf("unsigned recorder: %v", err)
		}
		evidence.close()
		if !strings.Contains(stderr.String(), "Receipts: disabled") {
			t.Fatalf("unsigned receipt warning missing: %q", stderr.String())
		}
	})
	t.Run("recorder obstruction", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Redact = false
		badRecorderDir := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(badRecorderDir, []byte("x"), 0o600); err != nil {
			t.Fatalf("write recorder obstruction: %v", err)
		}
		cfg.FlightRecorder.Dir = badRecorderDir
		if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "creating Guard flight recorder") {
			t.Fatalf("recorder creation error = %v", err)
		}
	})
	t.Run("required unsigned receipts", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "required-receipts")
		cfg.FlightRecorder.Redact = false
		cfg.FlightRecorder.SignCheckpoints = false
		cfg.FlightRecorder.RequireReceipts = true
		if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "no healthy signed Guard receipt emitter") {
			t.Fatalf("required unsigned receipt error = %v", err)
		}
	})
	t.Run("invalid posture binding", func(t *testing.T) {
		_, privateKey, err := signing.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		keyPath := filepath.Join(t.TempDir(), "receipt.key")
		if err := signing.SavePrivateKey(privateKey, keyPath); err != nil {
			t.Fatalf("SavePrivateKey: %v", err)
		}
		cfg := config.Defaults()
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "posture-error")
		cfg.FlightRecorder.SigningKeyPath = keyPath
		cfg.FlightRecorder.SignCheckpoints = true
		cfg.FlightRecorder.RequireReceipts = true
		t.Setenv("PIPELOCK_POSTURE_PROOF", "relative-proof.json")
		if _, err := newGuardEvidence(t.Context(), cfg, nil, metrics.New(), io.Discard); err == nil || !strings.Contains(err.Error(), "loading Guard posture binding") {
			t.Fatalf("posture binding error = %v", err)
		}
	})
	t.Run("invalid destination", func(t *testing.T) {
		if _, err := guardDestinationGrants([]config.GuardService{{Name: "bad", Protocol: "bad", Host: "api.vendor.example", Port: 443}}); err == nil {
			t.Fatal("invalid Guard destination was accepted")
		}
	})
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

func TestGuardPreflightRefusesWorkspaceSymlinkThatBypassesWriteFloor(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink("/usr/local/bin", alias); err != nil {
		t.Fatalf("create workspace symlink: %v", err)
	}
	_, err := GuardPreflight(config.Defaults(), "", alias, []string{"/usr/bin/true"})
	if err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("dangerous workspace symlink preflight error = %v", err)
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
		{name: "invalid scanner pattern", mutate: func(cfg *config.Config) {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "invalid", Regex: "[", Severity: config.SeverityHigh})
		}, want: "create guard scanner"},
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

func TestGuardEvidenceRecordsPreExecApplicationWithoutClaimingCommandStart(t *testing.T) {
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
	evidence, err := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), io.Discard)
	if err != nil {
		t.Fatalf("newGuardEvidence: %v", err)
	}
	wantHash := strings.Repeat("a", 64)
	wantExecutionHash := strings.Repeat("b", 64)
	if err := evidence.activate(guardfs.ExecutionProof{ConfigPolicyHash: wantHash, EffectivePolicyHash: wantExecutionHash, Binary: "/usr/bin/true"}); err != nil {
		t.Fatalf("activate Guard evidence: %v", err)
	}
	evidence.close()

	found := false
	foundExecution := false
	foundPreExec := false
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
		if strings.Contains(string(contents), "guard-exec:"+wantExecutionHash) {
			foundExecution = true
		}
		if strings.Contains(string(contents), "landlock_applied_pre_exec") {
			foundPreExec = true
		}
		if strings.Contains(string(contents), "enforcement_success") {
			t.Fatalf("recorder overclaims successful command execution in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk recorder: %v", err)
	}
	if !found {
		t.Fatalf("recorder does not contain canonical Guard policy hash %s", wantHash)
	}
	if !foundExecution {
		t.Fatalf("recorder does not contain effective Guard execution digest %s", wantExecutionHash)
	}
	if !foundPreExec {
		t.Fatal("recorder does not contain signed pre-exec enforcement evidence")
	}
}

func TestGuardEvidenceActivationHandlesUnhealthyEmitter(t *testing.T) {
	_, privateKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(privateKey, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	for _, require := range []bool{true, false} {
		t.Run(fmt.Sprintf("require=%t", require), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.FlightRecorder.Enabled = true
			cfg.FlightRecorder.Dir = filepath.Join(t.TempDir(), "recorder")
			cfg.FlightRecorder.SigningKeyPath = keyPath
			cfg.FlightRecorder.RequireReceipts = require
			sc, scanErr := scanner.New(cfg)
			if scanErr != nil {
				t.Fatalf("scanner.New: %v", scanErr)
			}
			defer sc.Close()
			var stderr bytes.Buffer
			evidence, evidenceErr := newGuardEvidence(t.Context(), cfg, sc, metrics.New(), &stderr)
			if evidenceErr != nil {
				t.Fatalf("newGuardEvidence: %v", evidenceErr)
			}
			defer evidence.close()
			evidence.emitter.MarkUnhealthy(errors.New("test failure"))
			proof := guardfs.ExecutionProof{ConfigPolicyHash: strings.Repeat("a", 64), EffectivePolicyHash: strings.Repeat("b", 64), Binary: "/usr/bin/true"}
			activationErr := evidence.activate(proof)
			if require && (activationErr == nil || !strings.Contains(activationErr.Error(), "session_open")) {
				t.Fatalf("required activation error = %v", activationErr)
			}
			if !require && (activationErr != nil || !strings.Contains(stderr.String(), "UNVERIFIED")) {
				t.Fatalf("best-effort activation error=%v stderr=%q", activationErr, stderr.String())
			}
		})
	}
}
