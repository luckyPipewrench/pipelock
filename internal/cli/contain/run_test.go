// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
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
		emitPosture: func(configFile, outputDir string) (string, error) {
			postureConfig = configFile
			postureOutput = outputDir
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
		emitPosture: func(string, string) (string, error) { return "/unused", nil },
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
		emitPosture: func(string, string) (string, error) { return "/unused", nil },
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
		emitPosture: func(string, string) (string, error) {
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
		emitPosture: func(string, string) (string, error) {
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
		emitPosture: func(string, string) (string, error) { return "/unused", nil },
	}
	err := runContainRun(context.Background(), nil, io.Discard, io.Discard, runEnv, containRunOptions{}, []string{"../claude"})
	if err == nil || !strings.Contains(err.Error(), "invalid tool name") {
		t.Fatalf("err = %v, want invalid tool name", err)
	}
}
