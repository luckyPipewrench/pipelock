// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ciWorkflow returns the CI workflow source.
func ciWorkflow(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", ".github", "workflows", "ci.yaml")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}
	return string(data)
}

// TestTrustedScanRunsHelpersFromTheTrustedWorktree pins where the diff-generation
// helpers are executed from.
//
// The security-scan job builds its scanner from origin/main so that a pull
// request cannot supply the tool that inspects it. That guarantee is worth
// nothing if the SCRIPTS feeding that tool come from the pull request checkout:
// a pull request could replace generate-trusted-diff.sh with one that emits an
// empty diff, and the job would report a clean scan having read nothing.
//
// That is not hypothetical. It was the state of the job when it was first
// written, and it was caught in review rather than by any check, which is why
// this test exists. Fixing the instance does not stop it drifting back.
func TestTrustedScanRunsHelpersFromTheTrustedWorktree(t *testing.T) {
	t.Parallel()

	workflow := ciWorkflow(t)

	helpers := []string{
		"generate-trusted-diff.sh",
		"test-generate-trusted-diff.sh",
	}

	for _, helper := range helpers {
		found := false
		for _, line := range strings.Split(workflow, "\n") {
			if !strings.Contains(line, helper) {
				continue
			}
			found = true
			if !strings.Contains(line, "trusted-main") {
				t.Errorf("%s is invoked from the pull request checkout:\n  %s\nrun it from ${RUNNER_TEMP}/trusted-main so the pull request cannot supply the script that feeds the scanner", helper, strings.TrimSpace(line))
			}
		}
		if !found {
			t.Errorf("no invocation of %s found in the CI workflow; if the job was restructured, update this test rather than deleting it", helper)
		}
	}
}

// TestTrustedScanDoesNotInstallAReleasedScanner pins that the gate builds its
// scanner rather than downloading one.
//
// A published release is frozen at the last tag, so a scanner fix on the default
// branch does not reach the gate until the next release ships. That produced a
// repository-wide block: the whole-file-deletion fix in #1145 was on main and
// absent from v3.3.0, so every pull request deleting a file failed with a
// parser error reported as "Secrets detected in PR diff". The general form is
// worse than that instance, because the next such lag could be a MISSED
// detection rather than a visible false alarm.
func TestTrustedScanDoesNotInstallAReleasedScanner(t *testing.T) {
	t.Parallel()

	workflow := ciWorkflow(t)

	scanJob := regexp.MustCompile(`(?s)\n  security-scan:\n.*?\n  [a-z][a-z0-9-]*:\n`).FindString(workflow)
	if scanJob == "" {
		t.Fatal("could not locate the security-scan job; if the job was renamed, update this test rather than deleting it")
	}

	if strings.Contains(scanJob, "luckyPipewrench/pipelock@") {
		t.Error("the security-scan job installs a published Pipelock release; build the scanner from origin/main instead so the gate is never behind its own fixes")
	}
	if !strings.Contains(scanJob, "origin/main") {
		t.Error("the security-scan job does not build from origin/main; the scanner that judges a branch must be current and must not come from the branch")
	}
}
