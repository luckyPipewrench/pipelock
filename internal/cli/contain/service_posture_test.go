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
	probe.readLink = func(path string) (string, error) {
		if path == "/proc/self/ns/net" || path == "/proc/1/ns/net" {
			return "net:[1]", nil
		}
		return "net:[2]", nil
	}
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
			if !env.prelaunch {
				t.Fatal("preflight did not run in pre-launch mode")
			}
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
		hostNamespace:   true,
	}, []string{"claude", "--help"})
	if err != nil {
		t.Fatalf("runContainRun service posture: %v\n%s", err, out.String())
	}
	if namespaceAsserted || !emitted {
		t.Fatalf("namespace asserted in host half=%v emitted=%v, want false/true", namespaceAsserted, emitted)
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
		name      string
		probeCode int
		code      int
		runErr    error
		wantErr   string
	}{
		{name: "unreadable", code: 1},
		{name: "identity switch denied", probeCode: 1, code: 1, wantErr: "cannot switch to " + testAgentUser + " to check signing-key isolation"},
		{name: "readable", code: 0, wantErr: "could forge its own containment evidence"},
		{name: "unknown exit", code: 2, wantErr: "sudo exit 2"},
		{name: "probe error", runErr: errors.New("exec failed"), wantErr: "check signing-key isolation"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			readProbeCalled := false
			env := &probeEnv{
				agentUserName: testAgentUser,
				runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
					if name != "sudo" || len(args) < 7 || args[0] != "-n" || args[1] != "-u" || args[2] != testAgentUser || args[3] != "--" || args[4] != "test" {
						t.Fatalf("unexpected identity probe: %s %v", name, args)
					}
					if args[5] == "-e" && args[6] == "/" {
						return "", tc.probeCode, nil
					}
					if args[5] != "-r" || args[6] != "/operator/receipt.key" {
						t.Fatalf("unexpected key probe: %v", args)
					}
					readProbeCalled = true
					return "probe output", tc.code, tc.runErr
				},
			}
			cfg := config.Defaults()
			cfg.FlightRecorder.SigningKeyPath = "/operator/receipt.key"
			err := verifyAgentCannotReadSigningKey(context.Background(), env, cfg)
			if readProbeCalled == (tc.probeCode != 0) {
				t.Fatalf("readability probe called = %t after identity probe exit %d", readProbeCalled, tc.probeCode)
			}
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

// The documented recipe runs ExecStartPre inside the agent namespace. The
// in-namespace half attests that namespace, then must hand the containment
// preflight to a process in the host namespace and sign nothing itself.
func TestRunContainServicePostureAgentNamespaceHalfDelegatesToHost(t *testing.T) {
	var gotArgs []string
	asserted := false
	runEnv := containRunEnv{
		probe:  allPassEnv(t),
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		assertServiceNamespace: func(context.Context, netnsAssertEnv) error {
			asserted = true
			return nil
		},
		runInHostNamespace: func(_ context.Context, _, _ io.Writer, args []string) error {
			gotArgs = args
			return nil
		},
		emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
			t.Fatal("agent-namespace half signed posture itself")
			return postureEmission{}, nil
		},
	}
	opts := containRunOptions{configFile: "/etc/pipelock/pipelock.yaml", port: 9999, postureOutput: "/var/lib/posture", servicePrestart: true}
	if err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, opts, []string{"claude", "ask"}); err != nil {
		t.Fatalf("runContainRun: %v", err)
	}
	if !asserted {
		t.Fatal("namespace was not attested before delegating")
	}
	want := "contain service-posture --host-namespace --config /etc/pipelock/pipelock.yaml --port 9999 --posture-output /var/lib/posture -- claude ask"
	if strings.Join(gotArgs, " ") != want {
		t.Fatalf("host args = %q, want %q", strings.Join(gotArgs, " "), want)
	}
}

func TestRunContainServicePostureAgentNamespaceHalfRefusals(t *testing.T) {
	assertOK := func(context.Context, netnsAssertEnv) error { return nil }
	tests := []struct {
		name    string
		env     func(*containRunEnv)
		wantErr string
	}{
		{"host preflight failure refuses launch", func(e *containRunEnv) {
			e.runInHostNamespace = func(context.Context, io.Writer, io.Writer, []string) error { return errors.New("exit status 1") }
		}, "host-side preflight"},
		{"missing host runner refuses launch", func(e *containRunEnv) { e.runInHostNamespace = nil }, "host-namespace preflight is unavailable"},
		{"attestation failure never reaches host", func(e *containRunEnv) {
			e.assertServiceNamespace = func(context.Context, netnsAssertEnv) error { return errors.New("mismatch") }
			e.runInHostNamespace = func(context.Context, io.Writer, io.Writer, []string) error {
				t.Fatal("host half ran after failed attestation")
				return nil
			}
		}, "outside the managed agent namespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runEnv := containRunEnv{
				probe:                  allPassEnv(t),
				launch:                 func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
				assertServiceNamespace: assertOK,
				runInHostNamespace:     func(context.Context, io.Writer, io.Writer, []string) error { return nil },
				emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
					return postureEmission{}, nil
				},
			}
			tc.env(&runEnv)
			err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{servicePrestart: true}, []string{"claude"})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// The host half must itself be in the initial namespace, and probe 3 there
// must still fail closed when the managed table is missing.
func TestRunContainServicePostureHostHalfProbe3(t *testing.T) {
	tests := []struct {
		name     string
		selfNS   string
		nftOut   string
		nftCode  int
		wantErr  string
		wantSign bool
	}{
		{name: "host namespace with managed table signs", selfNS: "net:[1]", wantSign: true},
		{name: "managed table missing fails probe 3", selfNS: "net:[1]", nftOut: "Error: No such file or directory", nftCode: 1, wantErr: "probe 3"},
		{name: "agent namespace refused before any probe", selfNS: "net:[2]", wantErr: "not the host network namespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe := allPassEnv(t)
			probe.readLink = func(path string) (string, error) {
				switch path {
				case "/proc/self/ns/net":
					return tc.selfNS, nil
				case "/proc/1/ns/net":
					return "net:[1]", nil
				}
				return "net:[2]", nil
			}
			baseRun := probe.runCmd
			probe.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if containsArg(args, "list") && containsArg(args, "chain") && tc.nftCode != 0 {
					return tc.nftOut, tc.nftCode, nil
				}
				return baseRun(ctx, name, args...)
			}
			signed := false
			runEnv := containRunEnv{
				probe:  probe,
				launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
				assertServiceNamespace: func(context.Context, netnsAssertEnv) error {
					t.Fatal("host half re-attested the agent namespace")
					return nil
				},
				loadConfig: func(string) (*config.Config, error) {
					cfg := config.Defaults()
					cfg.FlightRecorder.SigningKeyPath = "/operator/receipt.key"
					return cfg, nil
				},
				emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
					signed = true
					return postureEmission{path: "/p"}, nil
				},
			}
			err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{
				configFile: defaultContainConfigPath, postureOutput: defaultContainPostureDir, servicePrestart: true, hostNamespace: true,
			}, []string{"claude"})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if signed != tc.wantSign {
				t.Fatalf("signed = %v, want %v", signed, tc.wantSign)
			}
		})
	}
}

func TestServicePostureHostNamespaceFlagIsHidden(t *testing.T) {
	cmd := servicePostureCmdWithEnv(servicePostureCommandEnv{})
	flag := cmd.Flags().Lookup("host-namespace")
	if flag == nil || !flag.Hidden {
		t.Fatalf("host-namespace flag = %+v, want hidden", flag)
	}
}
