// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// These assertions target the EXECUTED commands of the security-scan job, never
// workflow prose.
//
// An earlier version of this file searched the raw workflow text, which meant a
// comment, a step display name, or an `echo` could satisfy every check while the
// job invoked no scanner at all. Review caught that, and it is the same defect
// class the tests exist to prevent: a check that reads as coverage and verifies
// nothing. Match on what runs, reached through the parsed job.

type workflowStep struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	If   string `yaml:"if"`
	Run  string `yaml:"run"`
	// ContinueOnError is any-typed because YAML admits several shapes here:
	// omitted, null, blank, a bool, or a `${{ }}` expression string.
	ContinueOnError any `yaml:"continue-on-error"`
}

type workflowJob struct {
	If              string         `yaml:"if"`
	ContinueOnError any            `yaml:"continue-on-error"`
	Steps           []workflowStep `yaml:"steps"`
}

// continueOnErrorFailsOpen reports whether a continue-on-error value could let a
// failing step or job report success.
//
// Omitted, null and explicit false are safe. `true` is an outright fail-open: the
// scan would run, find secrets, exit non-zero, and the job would still pass. An
// expression is rejected because its value is not decidable here, and a gate
// whose fail-open-ness depends on runtime context is not a gate.
func continueOnErrorFailsOpen(v any) (bool, string) {
	switch value := v.(type) {
	case nil:
		return false, ""
	case bool:
		if value {
			return true, "true"
		}
		return false, ""
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || strings.EqualFold(trimmed, "false") {
			return false, ""
		}
		return true, trimmed
	default:
		return true, fmt.Sprintf("%v", value)
	}
}

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

// securityScanSteps returns the parsed steps of the gating scan job.
func securityScanSteps(t *testing.T) []workflowStep {
	t.Helper()

	path := filepath.Join("..", "..", ".github", "workflows", "ci.yaml")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read ci workflow: %v", err)
	}

	var parsed workflowFile
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parse ci workflow: %v", err)
	}

	job, ok := parsed.Jobs["security-scan"]
	if !ok {
		t.Fatal("no security-scan job; if the gating job was renamed, update this test rather than deleting it")
	}
	// A condition on the gating job is a way to switch the scan off while every
	// step below still reads as present. The gate must run on every pull
	// request, so it carries no condition at all.
	if strings.TrimSpace(job.If) != "" {
		t.Fatalf("the security-scan job is conditional (if: %q); a gate that can be skipped is not a gate", job.If)
	}
	if failsOpen, value := continueOnErrorFailsOpen(job.ContinueOnError); failsOpen {
		t.Fatalf("the security-scan job sets continue-on-error: %s; the scan would find secrets, fail, and the job would still report success", value)
	}
	if len(job.Steps) == 0 {
		t.Fatal("security-scan job has no steps")
	}
	return job.Steps
}

// runStepsContaining returns UNCONDITIONAL steps whose executed shell contains
// needle.
//
// Conditional steps are excluded deliberately. Every required command could be
// placed behind `if: ${{ false }}` and the job would still look complete while
// scanning nothing, so a command only counts as part of the contract when it
// runs on every invocation of the job. This job has no conditional steps today;
// if a legitimate one is added, extend the contract explicitly rather than
// relaxing this helper.
func runStepsContaining(steps []workflowStep, needle string) []workflowStep {
	var out []workflowStep
	for _, s := range steps {
		if s.Run == "" || !strings.Contains(s.Run, needle) {
			continue
		}
		if strings.TrimSpace(s.If) != "" {
			continue
		}
		// A required command inside a continue-on-error step does not enforce
		// anything: it can fail and the job still passes.
		if failsOpen, _ := continueOnErrorFailsOpen(s.ContinueOnError); failsOpen {
			continue
		}
		out = append(out, s)
	}
	return out
}

// TestTrustedScanRunsHelpersFromTheTrustedWorktree pins where the diff helpers
// are executed from.
//
// The job builds its scanner from origin/main so a pull request cannot supply
// the tool that inspects it. That guarantee is worth nothing if the SCRIPTS
// feeding the tool come from the pull request checkout: a pull request could
// replace generate-trusted-diff.sh with one emitting an empty diff, and the job
// would report a clean scan having read nothing. That was the state of the job
// when first written and it was caught in review.
func TestTrustedScanRunsHelpersFromTheTrustedWorktree(t *testing.T) {
	t.Parallel()

	steps := securityScanSteps(t)

	for _, helper := range []string{"generate-trusted-diff.sh", "test-generate-trusted-diff.sh"} {
		t.Run(helper, func(t *testing.T) {
			t.Parallel()

			invoking := runStepsContaining(steps, helper)
			if len(invoking) == 0 {
				t.Fatalf("no executed step invokes %s; if the job was restructured, update this test rather than deleting it", helper)
			}

			for _, step := range invoking {
				// Join line continuations so a wrapped command is judged whole.
				run := strings.ReplaceAll(step.Run, "\\\n", " ")
				for _, line := range strings.Split(run, "\n") {
					if !strings.Contains(line, helper) {
						continue
					}
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						continue
					}
					if !strings.Contains(line, "${RUNNER_TEMP}/trusted-main/") {
						t.Errorf("%s runs from the pull request checkout:\n  %s\ninvoke it from ${RUNNER_TEMP}/trusted-main so a pull request cannot supply the script that feeds the scanner", helper, strings.TrimSpace(line))
					}
				}
			}
		})
	}
}

// TestTrustedScanBuildsItsOwnScanner pins that the gate builds the scanner from
// the default branch rather than installing a published release.
//
// A release is frozen at the last tag, so a scanner fix on main does not reach
// the gate until the next release ships. That produced a repository-wide block:
// the whole-file-deletion fix in #1145 was on main and absent from v3.3.0, so
// every pull request deleting a file failed with a parser error reported as
// "Secrets detected in PR diff". The general form is worse than the instance,
// because the next lag could be a MISSED detection rather than a visible false
// alarm.
func TestTrustedScanBuildsItsOwnScanner(t *testing.T) {
	t.Parallel()

	steps := securityScanSteps(t)

	for _, step := range steps {
		if strings.Contains(step.Uses, "luckyPipewrench/pipelock@") {
			t.Errorf("the scan job installs a published Pipelock release via %q; build from origin/main so the gate is never behind its own fixes", step.Uses)
		}
		if step.Run != "" && strings.Contains(step.Run, "releases/latest") {
			t.Errorf("the scan job downloads a released scanner:\n  %s", strings.TrimSpace(step.Run))
		}
	}

	// The build must fetch the default branch, materialise it, and compile from
	// there. Asserting only that the string "origin/main" appears somewhere
	// would be satisfied by a comment.
	required := []struct {
		needle string
		why    string
	}{
		{"git fetch", "the build must fetch the default branch rather than trusting the checked-out tree"},
		{"git worktree add", "the build must compile from a separate worktree so no pull request file contributes to the binary"},
		{"go build", "the scanner must be compiled, not downloaded"},
		{"./cmd/pipelock", "the build must target the scanner command"},
	}
	for _, req := range required {
		if len(runStepsContaining(steps, req.needle)) == 0 {
			t.Errorf("no executed step runs %q: %s", req.needle, req.why)
		}
	}

	if len(runStepsContaining(steps, "git scan-diff")) == 0 {
		t.Error("no executed step runs the scanner; the job can look intact while scanning nothing")
	}
}

// TestContinueOnErrorFailsOpenAcrossYAMLShapes covers every form YAML admits
// for continue-on-error, because the parsed type differs per shape and getting
// one wrong silently permits a fail-open gate.
func TestContinueOnErrorFailsOpenAcrossYAMLShapes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		value     any
		failsOpen bool
	}{
		{name: "omitted", value: nil},
		{name: "explicit null", value: nil},
		{name: "blank", value: ""},
		{name: "explicit false", value: false},
		{name: "string false", value: "false"},
		{name: "explicit true", value: true, failsOpen: true},
		{name: "string true", value: "true", failsOpen: true},
		{name: "expression", value: "${{ matrix.experimental }}", failsOpen: true},
		{name: "unexpected type", value: 1, failsOpen: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := continueOnErrorFailsOpen(tc.value)
			if got != tc.failsOpen {
				t.Fatalf("continueOnErrorFailsOpen(%#v) = %v, want %v", tc.value, got, tc.failsOpen)
			}
		})
	}
}
