// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// The routing bug these tests exist for was invisible to every existing CLI
// test, and the reason is worth stating: a test that calls cmd.SetOut(&buf) IS
// setting the writer cobra's Print* family resolves to, so the output appears
// in the buffer the test named "stdout" whether or not production would send it
// there. Production never called SetOut, so Print* fell through to stderr.
//
// So these tests do not install writers at all. They re-exec this test binary
// as a child process, have it run the real root command, and read the child's
// actual stdout and stderr pipes. That is the state a person running the binary
// is in, and it keeps the two streams genuinely separate rather than separated
// by agreement.
//
// A subprocess is also what makes this safe to run alongside the 24 parallel
// tests in this package. Replacing os.Stdout in-process would swap the file
// under any test running concurrently, and rootCmd itself reads os.Stdout when
// it is constructed, so a parallel test building a command inside the capture
// window would write into this test's pipe and then into a closed descriptor.

// routingHelperEnv carries the argument vector to the re-executed child. Its
// presence is what tells TestMain to run the CLI instead of the test suite.
const routingHelperEnv = "PIPELOCK_TEST_CLI_ROUTING_ARGS"

// runCLIHelper reports whether this process was started to act as the CLI, and
// if so runs the real root command and exits. TestMain calls it first.
func runCLIHelper() {
	encoded, ok := os.LookupEnv(routingHelperEnv)
	if !ok {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(encoded), &args); err != nil {
		os.Exit(2)
	}
	// No SetOut, no SetErr. Whatever routing production has is what runs here.
	//
	// The error handling mirrors cmd/pipelock/main.go deliberately. The root
	// command sets SilenceErrors, so main is what prints the error and picks the
	// status. An earlier version of this helper just exited 1, which made the
	// child produce an empty stderr and hid whether the CLI reports a failure
	// usefully or only fails silently.
	cmd := rootCmd()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(cliutil.ExitCodeOf(err))
	}
	os.Exit(0)
}

// runCLI executes the given pipelock arguments in a child process and returns
// its stdout, stderr, and exit code.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("encode args: %v", err)
	}

	// os.Executable resolves this test binary rather than trusting os.Args[0],
	// which the caller controls and which may be a relative path.
	//
	// -test.run matches nothing, so if the helper guard ever fails to fire the
	// child runs zero tests and reports empty output rather than re-running the
	// whole suite inside itself. The pipelock arguments under test travel in an
	// environment variable, so the argument vector here stays constant.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test binary: %v", err)
	}
	child := exec.CommandContext(t.Context(), self, "-test.run=XXX_NO_SUCH_TEST")

	// Drop any inherited copy of the helper variable before appending this
	// call's. Two entries for one name is resolvable-but-unspecified, and an
	// ambient value winning would silently run a different command than the
	// test asked for.
	// The child stands in for a person running the binary, so it gets a home of
	// its own. TestMain isolates the data directory for the whole package and
	// the child inherits that; the home directory was not isolated, which left
	// the child reading the developer's real one.
	//
	// Both spellings are set, because os.UserHomeDir reads HOME on Unix and
	// USERPROFILE on Windows, and os.UserConfigDir reads APPDATA there.
	// Isolating only the Unix name would leave the child unisolated on the one
	// platform this project has only just started running on.
	home := t.TempDir()
	isolated := map[string]string{
		"HOME":           home,
		"USERPROFILE":    home,
		"APPDATA":        filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA":   filepath.Join(home, "AppData", "Local"),
		routingHelperEnv: string(encoded),
	}

	env := make([]string, 0, len(os.Environ())+len(isolated))
	for _, kv := range os.Environ() {
		// Drop any inherited copy of a name being set below. Two entries for one
		// name is resolvable-but-unspecified, and an ambient value winning would
		// silently run a different command, or in a different home, than the
		// test asked for.
		name, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, replaced := isolated[name]; replaced {
				continue
			}
		}
		env = append(env, kv)
	}
	for name, value := range isolated {
		env = append(env, name+"="+value)
	}
	child.Env = env

	var outBuf, errBuf bytes.Buffer
	child.Stdout = &outBuf
	child.Stderr = &errBuf

	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

func TestCLISendsResultsToStdout(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // a fragment of the result that must reach stdout
	}{
		{name: "version", args: []string{"version"}, want: "pipelock version"},
		{name: "audit score", args: []string{"audit", "score"}, want: "Pipelock Config Security Score"},
		{name: "generate docker-compose", args: []string{"generate", "docker-compose"}, want: "services:"},
		// check and simulate below are the SUCCESS paths. The failing-check case
		// in the next test proves a diagnostic stays on stderr; it says nothing
		// about where a successful run puts its result. simulate in particular
		// had a fix here and no test.
		{name: "check", args: []string{"check"}, want: "Using default config"},
		{name: "simulate", args: []string{"simulate"}, want: "Pipelock Attack Simulation"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, tc.args...)
			if code != 0 {
				t.Fatalf("%v exited %d\nstderr: %s", tc.args, code, stderr)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("result did not reach stdout.\nstdout: %q\nstderr: %q", stdout, stderr)
			}
			// Without this, a command writing the result to BOTH streams would
			// pass, and the test would prove nothing about routing.
			if strings.Contains(stderr, tc.want) {
				t.Errorf("result also leaked to stderr.\nstdout: %q\nstderr: %q", stdout, stderr)
			}
		})
	}
}

func TestCLIKeepsDiagnosticsOffStdout(t *testing.T) {
	// Routing results to stdout must not drag diagnostics along with them.
	// PrintErr* resolves through a separate writer that this change does not
	// touch, so a failure report stays on stderr and a caller redirecting
	// stdout to a file still sees why the command failed.
	stdout, stderr, code := runCLI(t, "check", "--config", "/nonexistent-pipelock-config.yaml")
	if code == 0 {
		t.Fatal("check accepted a config path that does not exist")
	}
	if !strings.Contains(stderr, "Config validation FAILED") {
		t.Errorf("failure report did not reach stderr.\nstderr: %q", stderr)
	}
	if strings.Contains(stdout, "Config validation FAILED") {
		t.Errorf("failure report leaked onto stdout.\nstdout: %q", stdout)
	}
}
