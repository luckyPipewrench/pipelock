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

func runReleaseImageNamespace(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("release image namespace script requires bash")
	}
	script, err := filepath.Abs("release-image-namespace.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Read the script so the Go test cache records it as an input; bash opening
	// it is invisible to the cache, and a cached pass would survive an edit.
	if _, err := os.ReadFile(script); err != nil { // #nosec G304 -- fixed path in this test's source tree.
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "bash", append([]string{script}, args...)...) // #nosec G204 -- script path is this test's source tree; arguments are test literals.
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestReleaseImageNamespaceMapsBothReleaseRepositories(t *testing.T) {
	for repository, want := range map[string]string{
		"luckyPipewrench/pipelock": "ghcr.io/luckypipewrench\n",
		"pipelab-org/pipelock":     "ghcr.io/pipelab-org\n",
	} {
		got, err := runReleaseImageNamespace(t, repository)
		if err != nil {
			t.Fatalf("%s: %v\n%s", repository, err, got)
		}
		if got != want {
			t.Fatalf("%s: namespace = %q, want %q", repository, got, want)
		}
	}
}

func TestReleaseImageNamespaceRejectsEveryOtherRepository(t *testing.T) {
	for _, repository := range []string{
		"",
		"luckypipewrench/pipelock",
		"LUCKYPIPEWRENCH/pipelock",
		"pipelab-org/Pipelock",
		"pipelab/pipelock",
		"someone/pipelock",
		"pipelab-org/pipelock-fork",
		"pipelab-org/pipelock/extra",
		" pipelab-org/pipelock",
		"pipelab-org/pipelock\n",
	} {
		got, err := runReleaseImageNamespace(t, repository)
		if err == nil {
			t.Fatalf("%q was accepted as %q", repository, got)
		}
		if !strings.Contains(got, "is not a Pipelock release repository") {
			t.Fatalf("%q: unexpected output %q", repository, got)
		}
	}
}

func TestReleaseImageNamespaceRequiresExactlyOneArgument(t *testing.T) {
	for _, args := range [][]string{nil, {"luckyPipewrench/pipelock", "pipelab-org/pipelock"}} {
		got, err := runReleaseImageNamespace(t, args...)
		if err == nil || !strings.Contains(got, "usage:") {
			t.Fatalf("args %q: err = %v, output = %q", args, err, got)
		}
	}
}
