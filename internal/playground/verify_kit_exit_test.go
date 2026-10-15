// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLiveKitScriptExitStatus(t *testing.T) {
	for _, osName := range []VerifyKitOS{VerifyKitOSLinux, VerifyKitOSMacOS, VerifyKitOSWindows} {
		for _, status := range []int{0, 7} {
			t.Run(fmt.Sprintf("%s/status%d", osName, status), func(t *testing.T) {
				name, body, err := liveKitScript(osName, PublishedOrchestratorPubKeyHex, false)
				if err != nil {
					t.Fatal(err)
				}
				if osName == VerifyKitOSWindows {
					// Check the Windows contract on every host; execute it on Windows CI.
					command := "pipelock-verifier.exe verify-run run --orchestrator-key " + PublishedOrchestratorPubKeyHex
					if !strings.Contains(body, command+"\r\nset \"verify_status=%errorlevel%\"\r\n") || !strings.HasSuffix(body, "exit /b %verify_status%\r\n") {
						t.Fatal("Windows launcher does not preserve verifier status")
					}
					if !strings.Contains(body, "if \"%verify_status%\"==\"0\" (echo result: VALID means") {
						t.Fatal("Windows launcher prints the VALID explanation regardless of verifier status")
					}
					if runtime.GOOS != "windows" {
						t.Skip("Windows cmd execution requires Windows; template contract checked")
					}
				} else if runtime.GOOS == "windows" {
					t.Skip("Bash launcher requires a POSIX host")
				}
				dir := t.TempDir()
				app := filepath.Join(dir, "app")
				if err := os.Mkdir(app, 0o750); err != nil {
					t.Fatal(err)
				}
				var command *exec.Cmd
				if osName == VerifyKitOSWindows {
					src := filepath.Join(dir, "verifier.go")
					if err := os.WriteFile(src, []byte(fmt.Sprintf("package main\nimport \"os\"\nfunc main() { os.Exit(%d) }\n", status)), 0o600); err != nil {
						t.Fatal(err)
					}
					build := exec.CommandContext(t.Context(), "go", "build", "-o", "app/pipelock-verifier.exe", "verifier.go")
					build.Dir = dir
					if out, err := build.CombinedOutput(); err != nil {
						t.Fatalf("build verifier: %v %s", err, out)
					}
					command = exec.CommandContext(t.Context(), "cmd", "/c", "Verify.bat")
				} else {
					verifier := fmt.Sprintf("#!/bin/sh\nexit %d\n", status)
					if err := os.WriteFile(filepath.Join(app, "pipelock-verifier"), []byte(verifier), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Join(app, "pipelock-verifier"), 0o700); err != nil { //nolint:gosec // The private verifier fixture must be executable by its owner.
						t.Fatal(err)
					}
					if osName == VerifyKitOSMacOS {
						command = exec.CommandContext(t.Context(), "bash", "Verify.command")
					} else {
						command = exec.CommandContext(t.Context(), "bash", "verify.sh")
					}
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				command.Dir = dir
				command.Stdin = strings.NewReader("x\n")
				out, err := command.CombinedOutput()
				got := 0
				if err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) {
						t.Fatal(err)
					}
					got = exit.ExitCode()
				}
				if got != status {
					t.Fatalf("exit = %d, want verifier exit %d: %s", got, status, out)
				}
				// The VALID explanation is printed only when the verifier passed.
				if saysValid := strings.Contains(string(out), "result: VALID means"); saysValid != (status == 0) {
					t.Fatalf("VALID line printed = %v for verifier exit %d: %s", saysValid, status, out)
				}
			})
		}
	}
}
