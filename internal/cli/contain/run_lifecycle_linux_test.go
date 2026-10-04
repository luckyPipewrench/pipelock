// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// These tests exercise run's real ordering and error propagation with an
// invocation-owned record sink. They never start a host service or prove live
// containment; the production constructor's privilege check remains separate.
func lifecycleRunTestEnv(t *testing.T) containRunEnv {
	t.Helper()
	return containRunEnv{
		probe:      allPassEnv(t),
		loadConfig: func(string) (*config.Config, error) { return config.Defaults(), nil },
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, _ string, _ *probeEnv, _ []string) (postureEmission, error) {
			return postureEmission{path: "fixture-proof.json", capsuleSHA256: strings.Repeat("c", 64)}, nil
		},
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
	}
}

func TestRunLifecycleConstructorFailurePreventsPreflight(t *testing.T) {
	sentinel := errors.New("synthetic lifecycle reservation failure")
	env := lifecycleRunTestEnv(t)
	env.probe.readFile = func(string) ([]byte, error) { t.Fatal("preflight ran before lifecycle reservation"); return nil, nil }
	env.launch = func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("launched after reservation failed")
		return nil
	}
	env.newLifecycle = func(dir string) (*containRunLifecycle, error) {
		if dir != "/synthetic/evidence" {
			t.Fatalf("constructor path=%q", dir)
		}
		return nil, sentinel
	}
	err := runContainRun(t.Context(), nil, io.Discard, io.Discard, env, containRunOptions{lifecycleOutput: "/synthetic/evidence"}, []string{"claude"})
	if !errors.Is(err, sentinel) || cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
		t.Fatalf("reservation error=%v", err)
	}
	if env.probe.lifecycle != nil {
		t.Fatal("failed reservation installed a lifecycle")
	}
}

func TestRunLifecycleDefaultAndNilKeepProductionGuard(t *testing.T) {
	for _, useDefault := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "default"}[useDefault], func(t *testing.T) {
			env := lifecycleRunTestEnv(t)
			if useDefault {
				env.newLifecycle = defaultContainRunEnv().newLifecycle
				if env.newLifecycle == nil {
					t.Fatal("default constructor absent")
				}
			}
			env.probe.readFile = func(string) ([]byte, error) {
				t.Fatal("preflight ran after rejected production constructor")
				return nil, nil
			}
			// Relative output is rejected even when tests run as root. Non-root must
			// fail at the privilege check before any path is opened.
			err := runContainRun(t.Context(), nil, io.Discard, io.Discard, env, containRunOptions{lifecycleOutput: "relative-evidence"}, []string{"claude"})
			want := "lifecycle output requires root"
			if isRoot() {
				want = "clean absolute new path"
			}
			if err == nil || !strings.Contains(err.Error(), want) || cliutil.ExitCodeOf(err) != cliutil.ExitConfig {
				t.Fatalf("production guard=%v; want %q", err, want)
			}
		})
	}
}

func TestRunLifecycleRejectsNonLaunchingModesBeforeConstructor(t *testing.T) {
	for _, mode := range []string{"dry-run", "service-prestart"} {
		t.Run(mode, func(t *testing.T) {
			env := lifecycleRunTestEnv(t)
			env.newLifecycle = func(string) (*containRunLifecycle, error) {
				t.Fatal("reserved lifecycle for nonlaunching mode")
				return nil, nil
			}
			opts := containRunOptions{lifecycleOutput: "/synthetic/evidence", dryRun: mode == "dry-run", servicePrestart: mode == "service-prestart"}
			err := runContainRun(t.Context(), nil, io.Discard, io.Discard, env, opts, []string{"claude"})
			if err == nil || !strings.Contains(err.Error(), "requires an actual contain run launch") {
				t.Fatalf("mode refusal=%v", err)
			}
		})
	}
}

func TestRunLifecycleFinalizationAndBoundHashes(t *testing.T) {
	for _, name := range []string{"preflight-error", "posture-error", "launch-error", "save-error", "close-error", "already-final"} {
		t.Run(name, func(t *testing.T) {
			env := lifecycleRunTestEnv(t)
			l, _ := lifecycleFixture()
			var records []containLifecycleRecord
			closeCount, launchCount := 0, 0
			primary := errors.New("synthetic " + name)
			saveErr, closeErr := errors.New("synthetic record write failure"), errors.New("synthetic record close failure")
			l.save = func(record containLifecycleRecord) error {
				records = append(records, record)
				if name == "save-error" {
					return saveErr
				}
				return nil
			}
			l.close = func() error {
				closeCount++
				if name == "close-error" {
					return closeErr
				}
				return nil
			}
			env.newLifecycle = func(string) (*containRunLifecycle, error) { return l, nil }
			cfg := config.Defaults()
			cfg.APIAllowlist = []string{"fixture.vendor.example"}
			env.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
			wantPosture := strings.Repeat("c", 64)
			if name == "preflight-error" {
				env.probe.readFile = func(string) ([]byte, error) { return nil, primary }
			}
			env.emitPosture = func(got *config.Config, _ ed25519.PrivateKey, _ string, probe *probeEnv, _ []string) (postureEmission, error) {
				if got != cfg || probe.lifecycle != l || l.record.ConfigSHA256 != cfg.Hash() || l.record.PolicySHA256 != cfg.CanonicalPolicyHash() {
					t.Fatal("posture did not receive the bound loaded configuration")
				}
				if name == "posture-error" {
					return postureEmission{}, primary
				}
				return postureEmission{path: "fixture-proof.json", capsuleSHA256: wantPosture}, nil
			}
			env.launch = func(ctx context.Context, probe *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
				launchCount++
				if ctx.Err() != nil || probe.lifecycle != l || l.record.PostureCapsuleSHA256 != wantPosture {
					t.Fatal("launch lost lifecycle context or posture identity")
				}
				if name == "already-final" {
					l.record.Final = true
					l.record.Phase = "complete"
					l.record.CleanupComplete = true
					return nil
				}
				return primary
			}
			opts := containRunOptions{lifecycleOutput: "/synthetic/evidence", postureOutput: defaultContainPostureDir}
			err := runContainRun(t.Context(), nil, io.Discard, io.Discard, env, opts, []string{"claude"})
			if closeCount != 1 {
				t.Fatalf("close count=%d", closeCount)
			}
			if name == "already-final" {
				if err != nil || len(records) != 0 || l.record.Phase != "complete" || !l.record.CleanupComplete {
					t.Fatalf("final witness overwritten: err=%v records=%+v lifecycle=%+v", err, records, l.record)
				}
				return
			}
			if !errors.Is(err, primary) || len(records) != 1 || !records[0].Final || records[0].Phase != "incomplete" || records[0].CleanupComplete {
				t.Fatalf("incomplete error/witness mismatch: err=%v records=%+v", err, records)
			}
			if !strings.Contains(records[0].Failure, primary.Error()) {
				t.Fatalf("witness lost primary failure: %+v", records[0])
			}
			if (name == "save-error") != errors.Is(err, saveErr) || (name == "close-error") != errors.Is(err, closeErr) {
				t.Fatalf("finalizer lost error identity: %v", err)
			}
			if (name == "preflight-error" || name == "posture-error") && launchCount != 0 {
				t.Fatal("launched after preflight/posture failure")
			}
			if name == "preflight-error" && (l.record.ConfigSHA256 != "" || l.record.PolicySHA256 != "" || l.record.PostureCapsuleSHA256 != "") {
				t.Fatal("early refusal invented configuration or posture identity")
			}
			if name == "posture-error" && l.record.PostureCapsuleSHA256 != "" {
				t.Fatal("failed emission invented posture identity")
			}
		})
	}
}
