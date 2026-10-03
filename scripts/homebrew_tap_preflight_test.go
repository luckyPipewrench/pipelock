// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHomebrewTapPreflightRequiresTheReleaseCredential(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("homebrew tap preflight requires bash")
	}
	command := homebrewPreflightCommand(t, "HTTP/1.1 200 OK\n", 0)
	command.Env = withoutCredentialEnv(command.Env)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "HOMEBREW_TAP_TOKEN is required") {
		t.Fatalf("missing credential error = %v, output = %q", err, output)
	}
}

func TestHomebrewTapPreflightAcceptsHTTP200(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("homebrew tap preflight requires bash")
	}
	command := homebrewPreflightCommand(t, "HTTP/1.1 200 OK\n", 0)
	command.Env = append(command.Env, "HOMEBREW_"+"TAP_TOKEN="+tapCredential())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("HTTP 200 failed: %v\n%s", err, output)
	}
}

func TestHomebrewTapPreflightRejectsNon200(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("homebrew tap preflight requires bash")
	}
	command := homebrewPreflightCommand(t, "HTTP/1.1 401 Unauthorized\n", 1)
	command.Env = append(command.Env, "GH_"+"TOKEN="+tapCredential())
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "status is not 200") {
		t.Fatalf("HTTP 401 error = %v, output = %q", err, output)
	}
}

func homebrewPreflightCommand(t *testing.T, statusLine string, exitCode int) *exec.Cmd {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	script := filepath.Join(filepath.Dir(sourceFile), "homebrew-tap-preflight.sh")
	binDir := t.TempDir()
	fake := filepath.Join(binDir, "gh")
	body := "#!/usr/bin/env bash\nif [ \"${GH_TOKEN:-}\" != " + tapCredential() + " ]; then printf 'gh saw the wrong credential\\n' >&2; exit 9; fi\nprintf '%s' " + shellQuote(statusLine) + "\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(fake, []byte(body), 0o700); err != nil { // #nosec G306 -- the fake gh must be executable.
		t.Fatalf("write fake gh: %v", err)
	}
	command := exec.CommandContext(t.Context(), "bash", script) // #nosec G204 -- script path is this test's source tree.
	command.Env = append(withoutCredentialEnv(os.Environ()), "PATH="+binDir+":/usr/bin:/bin")
	return command
}

func tapCredential() string {
	return "tap-" + "credential"
}

func withoutCredentialEnv(env []string) []string {
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "HOMEBREW_TAP_TOKEN=") || strings.HasPrefix(entry, "GH_TOKEN=") || strings.HasPrefix(entry, "GITHUB_TOKEN=") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	return "1"
}
