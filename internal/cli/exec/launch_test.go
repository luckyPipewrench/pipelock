// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package exec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

// A separate test process is required: Unix launch replaces the process.
func TestLaunchProcessHelper(t *testing.T) {
	mode := os.Getenv("PIPELOCK_EXEC_HELPER")
	if mode == "" {
		return
	}
	if mode == "child" {
		if os.Getenv("HTTP_PROXY") != "http://proxy.example:8888" || os.Getenv("NO_PROXY") != "" || os.Getenv("CUSTOM_PROXY") != "" {
			os.Exit(99)
		}
		code, err := strconv.Atoi(os.Getenv("PIPELOCK_EXEC_EXIT"))
		if err != nil {
			os.Exit(98)
		}
		os.Exit(code)
	}
	if mode == "missing" {
		cmd := &cobra.Command{}
		cmd.SetContext(t.Context())
		err := launch(cmd, []string{filepath.Join(os.TempDir(), "no-such-pipelock-exec-command")}, os.Environ())
		if err == nil {
			os.Exit(97)
		}
		os.Exit(0)
	}
	childEnv := make([]string, 0)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PIPELOCK_EXEC_HELPER=") {
			childEnv = append(childEnv, e)
		}
	}
	childEnv = append(childEnv, "PIPELOCK_EXEC_HELPER=child")
	childEnv = launchcontract.Merge(childEnv, launchcontract.Vars(launchcontract.Exec, "http://proxy.example:8888", "", "", ""))
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	err := launch(cmd, []string{os.Args[0], "-test.run=^TestLaunchProcessHelper$"}, childEnv)
	if err != nil {
		os.Exit(cliutil.ExitCodeOf(err))
	}
	os.Exit(0)
}

func TestLaunchExitCodeAndEnvironment(t *testing.T) {
	t.Parallel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{0, 7, 42} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(15*time.Second))
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestLaunchProcessHelper$")
			cmd.Env = append(os.Environ(), "PIPELOCK_EXEC_HELPER=launch", "PIPELOCK_EXEC_EXIT="+strconv.Itoa(code), "CUSTOM_PROXY=http://old.invalid", "NO_PROXY=*")
			output, err := cmd.CombinedOutput()
			got := 0
			if err != nil {
				got = cmd.ProcessState.ExitCode()
			}
			if got != code || ctx.Err() != nil {
				t.Fatalf("exit=%d want=%d err=%v output=%s", got, code, err, output)
			}
		})
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestLaunchProcessHelper$")
	cmd.Env = append(os.Environ(), "PIPELOCK_EXEC_HELPER=missing")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("missing command failure: %v %s", err, output)
	}
}

func TestShEnvironmentRoundTrip(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test runs on Unix")
	}
	var output bytes.Buffer
	value := "path with 'quote' $(false) `false`\nand newline"
	if err := printEnvironment(&output, "sh", []string{"CUSTOM_PROXY=old"}, []launchcontract.Variable{{Name: "NO_PROXY", Value: value}}); err != nil {
		t.Fatal(err)
	}
	output.WriteString("printf '%s' \"$NO_PROXY\"; test -z \"${CUSTOM_PROXY+x}\"")
	cmd := exec.CommandContext(t.Context(), "sh", "-c", output.String())
	cmd.Env = append(os.Environ(), "CUSTOM_PROXY=old")
	got, err := cmd.CombinedOutput()
	if err != nil || string(got) != value {
		t.Fatalf("round trip=%q err=%v", got, err)
	}
}
