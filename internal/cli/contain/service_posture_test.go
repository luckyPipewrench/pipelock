// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestServicePostureCmdRejectsMissingTool(t *testing.T) {
	cmd := servicePostureCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "usage: pipelock contain service-posture") {
		t.Fatalf("error = %v, want usage refusal", err)
	}
}

func TestServicePostureCmdRejectsInvalidPortBeforePrivilegeCheck(t *testing.T) {
	cmd := servicePostureCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--port", "0", "claude"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("error = %v, want port refusal", err)
	}
}

func TestServicePostureCmdRequiresRoot(t *testing.T) {
	cmd := servicePostureCmdWithEnv(servicePostureCommandEnv{
		supported: func() bool { return true },
		root:      func() bool { return false },
		run: func(*cobra.Command, containRunOptions, []string) error {
			t.Fatal("root refusal reached runner")
			return nil
		},
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"claude"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("error = %v, want root refusal", err)
	}
}

func TestServicePostureCmdRejectsUnsupportedPlatform(t *testing.T) {
	cmd := servicePostureCmdWithEnv(servicePostureCommandEnv{
		supported: func() bool { return false },
		root:      func() bool { return true },
		run: func(*cobra.Command, containRunOptions, []string) error {
			t.Fatal("unsupported platform reached runner")
			return nil
		},
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"claude"})
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "supported only on Linux") {
		t.Fatalf("error = %v, want platform refusal", err)
	}
}

func TestServicePostureCmdRunsValidatedRequest(t *testing.T) {
	called := false
	cmd := servicePostureCmdWithEnv(servicePostureCommandEnv{
		supported: func() bool { return true },
		root:      func() bool { return true },
		run: func(_ *cobra.Command, opts containRunOptions, args []string) error {
			called = true
			if !opts.servicePrestart || opts.port != 9999 || strings.Join(args, " ") != "claude ask" {
				t.Fatalf("opts=%+v args=%v", opts, args)
			}
			return nil
		},
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--port", "9999", "claude", "ask"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("service posture command: %v", err)
	}
	if !called {
		t.Fatal("validated request did not reach runner")
	}
}

func TestRunContainServicePostureSignsWithoutLaunching(t *testing.T) {
	probe := allPassEnv(t)
	namespaceAsserted := false
	emitted := false
	runEnv := containRunEnv{
		probe: probe,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			t.Fatal("service posture launched the agent")
			return nil
		},
		assertServiceNamespace: func(context.Context, netnsAssertEnv) error {
			namespaceAsserted = true
			return nil
		},
		loadConfig: func(string) (*config.Config, error) {
			cfg := config.Defaults()
			cfg.FlightRecorder.SigningKeyPath = "/operator/receipt.key"
			return cfg, nil
		},
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, _ string, env *probeEnv, args []string) (postureEmission, error) {
			emitted = true
			launch, err := containRunLaunchEvidence(env, args)
			if err != nil {
				t.Fatalf("containRunLaunchEvidence: %v", err)
			}
			if launch.Launcher != servicePostureLauncher {
				t.Fatalf("launcher = %q, want %q", launch.Launcher, servicePostureLauncher)
			}
			return postureEmission{path: "/var/lib/pipelock/contain/posture/proof.json"}, nil
		},
	}
	var out bytes.Buffer
	err := runContainRun(context.Background(), nil, &out, io.Discard, runEnv, containRunOptions{
		configFile:      defaultContainConfigPath,
		postureOutput:   defaultContainPostureDir,
		servicePrestart: true,
	}, []string{"claude", "--help"})
	if err != nil {
		t.Fatalf("runContainRun service posture: %v\n%s", err, out.String())
	}
	if !namespaceAsserted || !emitted {
		t.Fatalf("namespace=%v emitted=%v, want both true", namespaceAsserted, emitted)
	}
	if !strings.Contains(out.String(), "signed evidence for the pending unprivileged service launch") {
		t.Fatalf("output missing service posture result:\n%s", out.String())
	}
	if strings.Contains(out.String(), "pipelock contain run:") || !strings.Contains(out.String(), "pipelock contain service-posture: session contract") {
		t.Fatalf("service output used the wrong command label:\n%s", out.String())
	}
}

func TestRunContainServicePostureFailsBeforeSigningOutsideNamespace(t *testing.T) {
	probe := allPassEnv(t)
	emitted := false
	runEnv := containRunEnv{
		probe:  probe,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		assertServiceNamespace: func(context.Context, netnsAssertEnv) error {
			return errors.New("network namespace mismatch")
		},
		emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
			emitted = true
			return postureEmission{}, nil
		},
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{servicePrestart: true}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "outside the managed agent namespace") {
		t.Fatalf("error = %v, want namespace refusal", err)
	}
	if emitted {
		t.Fatal("namespace failure still emitted posture")
	}
}

func TestVerifyAgentCannotReadSigningKey(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		runErr  error
		wantErr string
	}{
		{name: "unreadable", code: 1},
		{name: "readable", code: 0, wantErr: "could forge its own containment evidence"},
		{name: "unknown exit", code: 2, wantErr: "sudo exit 2"},
		{name: "probe error", runErr: errors.New("exec failed"), wantErr: "check signing-key isolation"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := &probeEnv{
				agentUserName: testAgentUser,
				runCmd: func(context.Context, string, ...string) (string, int, error) {
					return "probe output", tc.code, tc.runErr
				},
			}
			cfg := config.Defaults()
			cfg.FlightRecorder.SigningKeyPath = "/operator/receipt.key"
			err := verifyAgentCannotReadSigningKey(context.Background(), env, cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyAgentCannotReadSigningKey: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyAgentCannotReadSigningKeyRejectsMissingInputs(t *testing.T) {
	cfg := config.Defaults()
	if err := verifyAgentCannotReadSigningKey(context.Background(), nil, cfg); err == nil || !strings.Contains(err.Error(), "probe is unavailable") {
		t.Fatalf("nil env error = %v", err)
	}
	env := &probeEnv{agentUserName: testAgentUser, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "", 1, nil
	}}
	if err := verifyAgentCannotReadSigningKey(context.Background(), env, cfg); err == nil || !strings.Contains(err.Error(), "signing_key_path is required") {
		t.Fatalf("missing key error = %v", err)
	}
}
