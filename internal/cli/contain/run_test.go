// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestDefaultContainRunEnv_WiresRealOperations(t *testing.T) {
	env := defaultContainRunEnv()
	if env.probe == nil {
		t.Fatal("probe env is nil")
	}
	if env.launch == nil {
		t.Fatal("launcher is nil")
	}
	if env.emitPosture == nil {
		t.Fatal("posture emitter is nil")
	}
}

func TestRunCmd_RejectsInvalidPortBeforePrivilegeChecks(t *testing.T) {
	cmd := runCmd()
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--port", "0", "claude"})

	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected invalid port error")
	}
	if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
		t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
	}
	if !strings.Contains(err.Error(), "port") {
		t.Fatalf("error = %v, want port validation failure", err)
	}
}

func TestRunCmd_RejectsMissingToolArg(t *testing.T) {
	cmd := runCmd()
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)

	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected missing tool argument error")
	}
	if !strings.Contains(err.Error(), "usage: pipelock contain run") {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestRunContainRun_VerifiesEmitsPostureThenLaunches(t *testing.T) {
	env := allPassEnv(t)
	var launched []string
	var postureConfig, postureOutput string
	runEnv := containRunEnv{
		probe: env,
		launch: func(_ context.Context, _ *probeEnv, args []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			launched = append([]string(nil), args...)
			return nil
		},
		emitPosture: func(configFile, outputDir string, probe *probeEnv, postureArgs []string) (string, error) {
			postureConfig = configFile
			postureOutput = outputDir
			if probe != env {
				t.Fatal("posture emitter did not receive probe env")
			}
			if got, want := strings.Join(postureArgs, " "), "claude --help"; got != want {
				t.Fatalf("posture args = %q, want %q", got, want)
			}
			return outputDir + "/proof.json", nil
		},
	}
	var out bytes.Buffer
	opts := containRunOptions{configFile: "/etc/pipelock/pipelock.yaml", postureOutput: "/var/lib/pipelock/contain/posture"}
	if err := runContainRun(context.Background(), strings.NewReader(""), &out, io.Discard, runEnv, opts, []string{"claude", "--help"}); err != nil {
		t.Fatalf("runContainRun: %v\nout:\n%s", err, out.String())
	}
	if got, want := strings.Join(launched, " "), "claude --help"; got != want {
		t.Fatalf("launched args = %q, want %q", got, want)
	}
	if postureConfig != opts.configFile || postureOutput != opts.postureOutput {
		t.Fatalf("posture args = %q %q", postureConfig, postureOutput)
	}
	if !strings.Contains(out.String(), "signed posture capsule") {
		t.Fatalf("output missing posture line:\n%s", out.String())
	}
}

func TestRunContainRun_RejectsIncompleteEnvironment(t *testing.T) {
	tests := []struct {
		name string
		env  containRunEnv
		args []string
		want string
	}{
		{
			name: "missing probe",
			env: containRunEnv{
				launch:      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
				emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
			},
			args: []string{"claude"},
			want: "preflight environment is missing",
		},
		{
			name: "missing launcher",
			env: containRunEnv{
				probe:       allPassEnv(t),
				emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
			},
			args: []string{"claude"},
			want: "launcher is unavailable",
		},
		{
			name: "missing posture emitter",
			env: containRunEnv{
				probe:  allPassEnv(t),
				launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
			},
			args: []string{"claude"},
			want: "posture emitter is unavailable",
		},
		{
			name: "missing args",
			env: containRunEnv{
				probe:       allPassEnv(t),
				launch:      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
				emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
			},
			want: "usage: pipelock contain run",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nilCtx context.Context
			err := runContainRun(nilCtx, nil, io.Discard, io.Discard, tt.env, containRunOptions{}, tt.args)
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if got := cliutil.ExitCodeOf(err); got != cliutil.ExitConfig {
				t.Fatalf("exit code = %d, want %d", got, cliutil.ExitConfig)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRunContainRun_FailsClosedBeforeLaunchWhenPreflightFails(t *testing.T) {
	env := allPassEnv(t)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, testAgentUser) && containsArg(args, curlPath) {
			return "200", 0, nil
		}
		return defaultRunForAllPass(name, args)
	}
	var launched bool
	runEnv := containRunEnv{
		probe: env,
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "cc_agent_egress_denied") {
		t.Fatalf("err = %v, want direct-egress preflight failure", err)
	}
	if launched {
		t.Fatal("launcher ran after failed preflight")
	}
}

func TestRunContainRun_FailsClosedWhenAgentCanSudoBackOut(t *testing.T) {
	env := allPassEnv(t)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testSudoCmd && containsArg(args, testAgentUser) && containsArg(args, "true") {
			return "", 0, nil
		}
		return defaultRunForAllPass(name, args)
	}
	runEnv := containRunEnv{
		probe:       env,
		launch:      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), containRunPrivilegeProbe) {
		t.Fatalf("err = %v, want privilege escape preflight failure", err)
	}
}

func TestRunContainRun_PostureFailureStopsLaunch(t *testing.T) {
	var launched bool
	runEnv := containRunEnv{
		probe: allPassEnv(t),
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(string, string, *probeEnv, []string) (string, error) {
			return "", errors.New("signing key missing")
		},
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"claude"})
	if err == nil || !strings.Contains(err.Error(), "posture capsule") {
		t.Fatalf("err = %v, want posture failure", err)
	}
	if launched {
		t.Fatal("launcher ran after posture failure")
	}
}

func TestRunContainRun_UnregisteredToolStopsBeforePosture(t *testing.T) {
	var posture bool
	runEnv := containRunEnv{
		probe:  allPassEnv(t),
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(string, string, *probeEnv, []string) (string, error) {
			posture = true
			return "/unused", nil
		},
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"notregistered"})
	if err == nil || !strings.Contains(err.Error(), "requested_tool_registered") {
		t.Fatalf("err = %v, want requested tool registration failure", err)
	}
	if posture {
		t.Fatal("posture emitted for unregistered tool")
	}
}

func TestParseAgentGIDs(t *testing.T) {
	// Primary first, supplementary preserved, duplicate primary dropped.
	got, err := parseAgentGIDs([]string{"966", "1001", "966"}, 966)
	if err != nil {
		t.Fatalf("parseAgentGIDs: %v", err)
	}
	if want := []uint32{966, 1001}; !equalGIDs(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Primary is injected even when GroupIds omits it.
	got, err = parseAgentGIDs([]string{"1001"}, 966)
	if err != nil {
		t.Fatalf("parseAgentGIDs: %v", err)
	}
	if want := []uint32{966, 1001}; !equalGIDs(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// The caller's root group (0) is never auto-added.
	got, err = parseAgentGIDs([]string{"966"}, 966)
	if err != nil {
		t.Fatalf("parseAgentGIDs: %v", err)
	}
	for _, g := range got {
		if g == 0 {
			t.Fatalf("group set %v must not include root group 0", got)
		}
	}

	// A non-numeric id fails closed rather than silently dropping a group.
	if _, err := parseAgentGIDs([]string{"abc"}, 966); err == nil {
		t.Fatal("expected error on non-numeric group id")
	}

	// Any root group membership fails closed; a contained launch must not
	// normalize a misconfigured agent account into a root-group process.
	if _, err := parseAgentGIDs([]string{"0"}, 966); err == nil {
		t.Fatal("expected error on supplementary root group")
	}
	if _, err := parseAgentGIDs([]string{"966"}, 0); err == nil {
		t.Fatal("expected error on primary root group")
	}
}

func equalGIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRunContainRun_RejectsInvalidToolName(t *testing.T) {
	runEnv := containRunEnv{
		probe:       allPassEnv(t),
		launch:      func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(string, string, *probeEnv, []string) (string, error) { return "/unused", nil },
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"../claude"})
	if err == nil || !strings.Contains(err.Error(), "invalid tool name") {
		t.Fatalf("err = %v, want invalid tool name", err)
	}
}

func TestProbeAgentPrivilegeEscapeDenied_FailPaths(t *testing.T) {
	tests := []struct {
		name   string
		runCmd runCommand
		want   string
	}{
		{
			name: "sudo canary cannot run",
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "", -1, errors.New("sudo unavailable")
			},
			want: "could not run",
		},
		{
			name: "agent user missing",
			runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "sudo: unknown user pipelock-agent", 1, nil
			},
			want: "user not present",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			env.runCmd = tt.runCmd

			status, detail := probeAgentPrivilegeEscapeDenied(context.Background(), env)
			if status != statusFail {
				t.Fatalf("status = %s, want %s (%s)", status, statusFail, detail)
			}
			if !strings.Contains(detail, tt.want) {
				t.Fatalf("detail = %q, want %q", detail, tt.want)
			}
		})
	}
}

func TestProbeRequestedToolRegistered_FailureDetails(t *testing.T) {
	tests := []struct {
		name string
		read func(string) ([]byte, error)
		want string
	}{
		{
			name: "read failure",
			read: func(string) ([]byte, error) {
				return nil, errors.New("permission denied")
			},
			want: "read ",
		},
		{
			name: "parse failure",
			read: func(string) ([]byte, error) {
				return []byte("malformed-entry\n"), nil
			},
			want: "parse ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			env.readFile = tt.read

			status, detail := probeRequestedToolRegistered(env, "claude")
			if status != statusFail {
				t.Fatalf("status = %s, want %s (%s)", status, statusFail, detail)
			}
			if !strings.Contains(detail, tt.want) {
				t.Fatalf("detail = %q, want %q", detail, tt.want)
			}
		})
	}
}

func TestEmitContainRunPosture_WritesSignedProof(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "flight-recorder.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("signing.SavePrivateKey: %v", err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfg := "mode: balanced\nflight_recorder:\n  enabled: false\n  signing_key_path: " + keyPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	outDir := filepath.Join(dir, "posture")
	env := allPassEnv(t)
	path, err := emitContainRunPosture(cfgPath, outDir, env, []string{"claude", "--help"})
	if err != nil {
		t.Fatalf("emitContainRunPosture: %v", err)
	}
	if path != filepath.Join(outDir, "proof.json") {
		t.Fatalf("proof path = %q, want %q", path, filepath.Join(outDir, "proof.json"))
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read proof: %v", err)
	}
	if !bytes.Contains(data, []byte(`"signature"`)) {
		t.Fatalf("proof missing signature: %s", data)
	}
	var capsule posturepkg.Capsule
	if err := json.Unmarshal(data, &capsule); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	if capsule.Evidence.ContainLaunch == nil {
		t.Fatalf("proof missing signed contain launch evidence: %s", data)
	}
	if capsule.Evidence.Containment == nil {
		t.Fatalf("proof missing signed containment evidence: %s", data)
	}
	if capsule.Evidence.Containment.KernelRuleHash == "" {
		t.Fatalf("proof containment evidence missing kernel rule hash: %+v", capsule.Evidence.Containment)
	}
	rules := renderNFTRules(1000, 988, 987, env.port, env.nftTable, env.nftChain)
	expectedRuleHash := sha256.Sum256([]byte(rules))
	if got, want := capsule.Evidence.Containment.KernelRuleHash, hex.EncodeToString(expectedRuleHash[:]); got != want {
		t.Fatalf("kernel rule hash = %q, want %q", got, want)
	}
	launch := capsule.Evidence.ContainLaunch
	if launch.Tool != "claude" || launch.CWD != "/home/"+testAgentUser || launch.Argc != 2 {
		t.Fatalf("launch evidence = %+v, want claude argc=2 cwd=/home/%s", launch, testAgentUser)
	}
	if got, want := strings.Join(launch.TargetGroups, ","), "987,1001"; got != want {
		t.Fatalf("target groups = %q, want %q", got, want)
	}
	if launch.ArgvSHA256 == "" || launch.EnvSHA256 == "" {
		t.Fatalf("launch evidence missing privacy-preserving hashes: %+v", launch)
	}
}

func TestContainRunContainmentEvidence_RejectsProbeFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*probeEnv)
		want   string
	}{
		{
			name: "nft boundary fails",
			mutate: func(env *probeEnv) {
				env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					if name == testNFT {
						return "table missing", 1, nil
					}
					return defaultRunForAllPass(name, args)
				}
			},
			want: "nft boundary probe did not pass: fail",
		},
		{
			name: "direct egress succeeds",
			mutate: func(env *probeEnv) {
				env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					if name == testSudoCmd && containsArg(args, testAgentUser) {
						return "200", 0, nil
					}
					return defaultRunForAllPass(name, args)
				}
			},
			want: "direct-egress probe did not pass: fail",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			tt.mutate(env)

			_, err := containRunContainmentEvidence(env, "987")
			if err == nil {
				t.Fatal("expected containment evidence error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestContainRunContainmentEvidence_RejectsMissingRuleHash(t *testing.T) {
	env := allPassEnv(t)
	env.nftRulesPath = ""

	_, err := containRunContainmentEvidence(env, "987")
	if err == nil {
		t.Fatal("expected containment evidence error")
	}
	if !strings.Contains(err.Error(), "nftables rules path is required") {
		t.Fatalf("error = %v, want missing rules path", err)
	}
}

func TestContainRunLaunchEvidence_RejectsInvalidUID(t *testing.T) {
	tests := []struct {
		name string
		uid  string
		want string
	}{
		{name: "malformed uid", uid: "not-a-uid", want: "parse uid"},
		{name: "root uid", uid: "0", want: "resolves to uid 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			origLookup := env.lookupUser
			env.lookupUser = func(name string) (*user.User, error) {
				u, err := origLookup(name)
				if err != nil {
					return nil, err
				}
				if name == testAgentUser {
					clone := *u
					clone.Uid = tt.uid
					return &clone, nil
				}
				return u, nil
			}

			_, err := containRunLaunchEvidence(env, []string{"claude"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEmitContainRunPosture_EmitFailure(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := emitContainRunPosture(cfgPath, t.TempDir(), allPassEnv(t), []string{"claude"})
	if err == nil {
		t.Fatal("expected posture emit error")
	}
	if !strings.Contains(err.Error(), "flight_recorder.signing_key_path") {
		t.Fatalf("error = %v, want missing signing key path", err)
	}
}

func TestEmitContainRunPosture_WriteFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "flight-recorder.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("signing.SavePrivateKey: %v", err)
	}
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	cfg := "mode: balanced\nflight_recorder:\n  enabled: false\n  signing_key_path: " + keyPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	outputPath := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(outputPath, []byte("occupied"), 0o600); err != nil {
		t.Fatalf("write output file: %v", err)
	}

	_, err = emitContainRunPosture(cfgPath, outputPath, allPassEnv(t), []string{"claude"})
	if err == nil {
		t.Fatal("expected proof write error")
	}
	if !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("error = %v, want output directory context", err)
	}
}

func TestEmitContainRunPosture_LoadFailure(t *testing.T) {
	_, err := emitContainRunPosture(filepath.Join(t.TempDir(), "missing.yaml"), t.TempDir(), allPassEnv(t), []string{"claude"})
	if err == nil {
		t.Fatal("expected config load error")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Fatalf("error = %v, want config load context", err)
	}
}
