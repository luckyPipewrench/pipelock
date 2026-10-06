// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func jobHelperEnv(mode string) []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PIPELOCK_WINDOWS_JOB_HELPER=") {
			env = append(env, e)
		}
	}
	return append(env, "PIPELOCK_WINDOWS_JOB_HELPER="+mode)
}

func TestWindowsJobHelper(t *testing.T) {
	mode := os.Getenv("PIPELOCK_WINDOWS_JOB_HELPER")
	if mode == "" {
		return
	}
	if mode == "launcher" {
		cmd := &cobra.Command{}
		cmd.SetContext(t.Context())
		err := launch(cmd, []string{os.Args[0], "-test.run=^TestWindowsJobHelper$"}, jobHelperEnv("child"))
		if err != nil {
			os.Exit(cliutil.ExitCodeOf(err))
		}
		os.Exit(0)
	}
	if mode == "child" {
		grandchild := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestWindowsJobHelper$")
		grandchild.Env = jobHelperEnv("descendant")
		grandchild.Stdin = os.Stdin
		if err := grandchild.Start(); err != nil {
			os.Exit(97)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%d,%d\n", os.Getpid(), grandchild.Process.Pid)
	}
	// A pipe read keeps both child processes alive without sleeps or polling.
	_, _ = os.Stdin.Read(make([]byte, 1))
	os.Exit(0)
}

func TestConsoleInterruptStaysWithChild(t *testing.T) {
	t.Parallel()
	if consoleInterruptHandled(windows.CTRL_C_EVENT) != 1 || consoleInterruptHandled(windows.CTRL_BREAK_EVENT) != 1 {
		t.Fatal("console interrupt was not left for the child")
	}
	if consoleInterruptHandled(windows.CTRL_CLOSE_EVENT) != 0 {
		t.Fatal("console close would keep the launcher alive and abandon the job")
	}
}

func TestWindowsJobKillsDescendants(t *testing.T) {
	t.Parallel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(15*time.Second))
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestWindowsJobHelper$")
	cmd.Env = jobHelperEnv("launcher")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() { scanner := bufio.NewScanner(stdout); scanner.Scan(); ready <- scanner.Text() }()
	var line string
	select {
	case line = <-ready:
	case <-ctx.Done():
		t.Fatal("child/descendant readiness deadline")
	}
	pids := strings.Split(line, ",")
	if len(pids) != 2 {
		t.Fatalf("readiness=%q", line)
	}
	var processes []windows.Handle
	for _, s := range pids {
		pid, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) // #nosec G115 -- ParseUint is bounded to 32 bits
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = windows.CloseHandle(handle) }()
		processes = append(processes, handle)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	for _, handle := range processes {
		status, err := windows.WaitForSingleObject(handle, 5000)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			t.Fatalf("job descendant survived: status=%d err=%v", status, err)
		}
	}
}

func TestWindowsPrintedEnvironmentRoundTrip(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"pwsh", "cmd"} {
		t.Run(format, func(t *testing.T) {
			t.Parallel()
			var script bytes.Buffer
			value := "path with spaces & punctuation"
			if err := printEnvironment(&script, format, []string{"CUSTOM_PROXY=old"}, []launchcontract.Variable{{Name: "NO_PROXY", Value: value}}); err != nil {
				t.Fatal(err)
			}
			var cmd *exec.Cmd
			if format == "pwsh" {
				script.WriteString("if (Test-Path Env:CUSTOM_PROXY) { exit 9 }; [Console]::Out.Write($env:NO_PROXY)")
				cmd = exec.CommandContext(t.Context(), "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script.String())
			} else {
				script.WriteString("if defined CUSTOM_PROXY exit /b 9\r\n<nul set /p \"=%NO_PROXY%\"\r\nexit /b 0\r\n")
				path := filepath.Join(t.TempDir(), "env.cmd")
				if err := os.WriteFile(path, append([]byte("@echo off\r\n"), script.Bytes()...), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd = exec.CommandContext(t.Context(), "cmd.exe", "/D", "/V:OFF", "/C", path)
			}
			cmd.Env = append(os.Environ(), "CUSTOM_PROXY=old")
			got, err := cmd.CombinedOutput()
			if err != nil || string(got) != value {
				t.Fatalf("round trip=%q err=%v", got, err)
			}
		})
	}
}
