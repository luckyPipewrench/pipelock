// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package gitprotect

import (
	"fmt"
	"os"
	"os/exec"
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
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	If   string            `yaml:"if"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	// ContinueOnError is any-typed because YAML admits several shapes here:
	// omitted, null, blank, a bool, or a `${{ }}` expression string.
	ContinueOnError any `yaml:"continue-on-error"`
}

// TestTrustedScanSelectsDiffEndpointsForEveryTrigger pins both event shapes
// accepted by the workflow. Pull-request-only fields are empty on a push, so
// using them unconditionally makes the main-branch gate fail before scanning.
// The explicit endpoint guards also keep an absent, zero, or unavailable ref
// from degrading into an empty or ambiguous scan.
func TestTrustedScanSelectsDiffEndpointsForEveryTrigger(t *testing.T) {
	t.Parallel()

	var steps []workflowStep
	for _, step := range runStepsContaining(securityScanSteps(t), "generate-trusted-diff.sh") {
		if step.Name == "Scan the diff" {
			steps = append(steps, step)
		}
	}
	if len(steps) != 1 {
		t.Fatalf("got %d unconditional diff-generation steps, want exactly 1", len(steps))
	}

	step := steps[0]
	if strings.TrimSpace(step.If) != "" {
		t.Fatalf("scan step is conditional (if: %q); the endpoint gate must run for every job invocation", step.If)
	}
	if got, want := step.Env["BASE_SHA"], "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}"; got != want {
		t.Fatalf("BASE_SHA expression = %q, want %q", got, want)
	}
	if got, want := step.Env["HEAD_SHA"], "${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}"; got != want {
		t.Fatalf("HEAD_SHA expression = %q, want %q", got, want)
	}
	for _, exactGuard := range []string{
		`if [[ -z "${BASE_SHA}" || -z "${HEAD_SHA}" || "${BASE_SHA}" == "${zero_sha}" || "${HEAD_SHA}" == "${zero_sha}" ]]; then`,
		`git rev-parse --verify --quiet "${BASE_SHA}^{commit}" >/dev/null || {`,
		`git rev-parse --verify --quiet "${HEAD_SHA}^{commit}" >/dev/null || {`,
	} {
		if !strings.Contains(step.Run, exactGuard) {
			t.Fatalf("scan step lacks exact fail-closed endpoint guard %q", exactGuard)
		}
	}

	repo, runnerTemp, baseSHA, headSHA := trustedScanTestRepo(t)
	scanScriptPath := filepath.Join(runnerTemp, "scan-step.sh")
	if err := os.WriteFile(scanScriptPath, []byte(step.Run), 0o600); err != nil {
		t.Fatalf("write scan-step fixture: %v", err)
	}
	zeroSHA := strings.Repeat("0", 40)
	for _, tc := range []struct {
		name             string
		baseSHA          string
		headSHA          string
		wantPass         bool
		wantRanGenerator bool
		wantRanScan      bool
	}{
		{name: "valid endpoints", baseSHA: baseSHA, headSHA: headSHA, wantPass: true, wantRanGenerator: true, wantRanScan: true},
		{name: "empty base", baseSHA: "", headSHA: headSHA},
		{name: "empty head", baseSHA: baseSHA, headSHA: ""},
		{name: "zero base", baseSHA: zeroSHA, headSHA: headSHA},
		{name: "zero head", baseSHA: baseSHA, headSHA: zeroSHA},
		{name: "unavailable base", baseSHA: strings.Repeat("a", 40), headSHA: headSHA},
		{name: "unavailable head", baseSHA: baseSHA, headSHA: strings.Repeat("b", 40)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, marker := range []string{"generator-ran", "scanner-ran", "pr.diff"} {
				_ = os.Remove(filepath.Join(runnerTemp, marker))
			}
			// #nosec G204 -- the script path names this test's temporary copy of the checked-in workflow step.
			cmd := exec.CommandContext(t.Context(), "bash", scanScriptPath)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "RUNNER_TEMP="+runnerTemp, "BASE_SHA="+tc.baseSHA, "HEAD_SHA="+tc.headSHA)
			output, err := cmd.CombinedOutput()
			if tc.wantPass && err != nil {
				t.Fatalf("scan step rejected valid endpoints: %v\n%s", err, output)
			}
			if !tc.wantPass && err == nil {
				t.Fatalf("scan step accepted invalid endpoints; output:\n%s", output)
			}
			_, generatorErr := os.Stat(filepath.Join(runnerTemp, "generator-ran"))
			if got := generatorErr == nil; got != tc.wantRanGenerator {
				t.Fatalf("generator execution = %t, want %t; output:\n%s", got, tc.wantRanGenerator, output)
			}
			_, scanErr := os.Stat(filepath.Join(runnerTemp, "scanner-ran"))
			if got := scanErr == nil; got != tc.wantRanScan {
				t.Fatalf("scanner execution = %t, want %t; output:\n%s", got, tc.wantRanScan, output)
			}
		})
	}
}

func trustedScanTestRepo(t *testing.T) (repo, runnerTemp, baseSHA, headSHA string) {
	t.Helper()
	repo = t.TempDir()
	runnerTemp = t.TempDir()
	runTrustedScanGitCommand(t, repo, "init", "--quiet")
	runTrustedScanGitCommand(t, repo, "config", "user.email", "test@example.invalid")
	runTrustedScanGitCommand(t, repo, "config", "user.name", "Pipelock Test")
	tracked := filepath.Join(repo, "tracked.txt")
	if err := os.WriteFile(tracked, []byte("base\n"), 0o600); err != nil {
		t.Fatalf("write base fixture: %v", err)
	}
	runTrustedScanGitCommand(t, repo, "add", "tracked.txt")
	runTrustedScanGitCommand(t, repo, "commit", "--quiet", "-m", "base")
	baseSHA = strings.TrimSpace(runTrustedScanGitCommand(t, repo, "rev-parse", "HEAD"))
	if err := os.WriteFile(tracked, []byte("head\n"), 0o600); err != nil {
		t.Fatalf("write head fixture: %v", err)
	}
	runTrustedScanGitCommand(t, repo, "add", "tracked.txt")
	runTrustedScanGitCommand(t, repo, "commit", "--quiet", "-m", "head")
	headSHA = strings.TrimSpace(runTrustedScanGitCommand(t, repo, "rev-parse", "HEAD"))

	scriptDir := filepath.Join(runnerTemp, "trusted-main", "scripts")
	if err := os.MkdirAll(scriptDir, 0o750); err != nil {
		t.Fatalf("create trusted script directory: %v", err)
	}
	generator := "#!/usr/bin/env bash\nset -euo pipefail\ntouch \"${RUNNER_TEMP}/generator-ran\"\ngit diff --binary \"$1\" \"$2\" > \"$3\"\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "generate-trusted-diff.sh"), []byte(generator), 0o600); err != nil {
		t.Fatalf("write fake diff generator: %v", err)
	}
	scanner := "#!/usr/bin/env bash\nset -euo pipefail\ncat >/dev/null\ntouch \"${RUNNER_TEMP}/scanner-ran\"\n"
	scannerPath := filepath.Join(runnerTemp, "pipelock")
	if err := os.WriteFile(scannerPath, []byte(scanner), 0o600); err != nil {
		t.Fatalf("write fake scanner: %v", err)
	}
	// #nosec G302 -- this temporary test fixture must be executable as the workflow scanner binary.
	if err := os.Chmod(scannerPath, 0o700); err != nil {
		t.Fatalf("make fake scanner executable: %v", err)
	}
	return repo, runnerTemp, baseSHA, headSHA
}

func runTrustedScanGitCommand(t *testing.T, dir string, args ...string) string {
	t.Helper()
	// #nosec G204 -- arguments are fixed Git fixture commands supplied by this test.
	cmd := exec.CommandContext(t.Context(), "git", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
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
