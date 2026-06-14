// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// DESIGN NOTE: This test drives pipelock's direct-egress containment probes
// (probe 8: pipelock-agent egress denied; probe 9: operator egress reachable)
// as a publishable conformance artifact. Rather than exporting the unexported
// probe/probeEnv internals from internal/cli/contain (which carry real
// sudo/curl/nft execution seams we must not widen for a test artifact), the
// contain package exposes ONE minimal entry point —
// contain.RunContainmentConformance(ctx, contain.ConformanceEnv{...}) — that
// runs those two probes against an injected canned command-runner and returns
// exported result records plus the aggregate exit code. This test builds that
// canned runner from external JSON fixtures under testdata/containment/ and
// asserts per-probe status + overall exit code against each fixture's
// .expect.json. The must-fail "leaky-egress" fixture proves the egress-denied
// test is real: if probe 8 ever stops failing when the agent reaches the
// internet directly, this test fails.

package conformance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain"
)

const containmentFixtureDir = "testdata/containment"

var expectedContainmentProbes = map[int]string{
	8: "cc_agent_egress_denied",
	9: "operator_egress_reachable",
}

// containmentRunRule is one canned command-match rule from a *.probe.json
// fixture: when the joined command line contains every Match substring, the
// runner returns Stdout + ExitCode.
type containmentRunRule struct {
	Match    []string `json:"match"`
	Stdout   string   `json:"stdout"`
	ExitCode int      `json:"exit_code"`
}

// containmentProbeFixture is the parsed *.probe.json input.
type containmentProbeFixture struct {
	AgentUser    string               `json:"agent_user"`
	OperatorUser string               `json:"operator_user"`
	Runs         []containmentRunRule `json:"runs"`
}

// containmentExpectProbe is one expected per-probe outcome.
type containmentExpectProbe struct {
	Probe  int    `json:"probe"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// containmentExpectFixture is the parsed *.expect.json input.
type containmentExpectFixture struct {
	ExitCode int                      `json:"exit_code"`
	Probes   []containmentExpectProbe `json:"probes"`
}

// loadContainmentProbe reads and parses a *.probe.json fixture. Fail-closed:
// any read/parse error or an empty run set fails the test rather than driving
// an under-specified runner.
func loadContainmentProbe(t *testing.T, path string) containmentProbeFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read probe fixture %s: %v", path, err)
	}
	var fx containmentProbeFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse probe fixture %s: %v", path, err)
	}
	if len(fx.Runs) == 0 {
		t.Fatalf("probe fixture %s has no runs (fail-closed: refusing to drive an empty runner)", path)
	}
	// A run rule with no match substrings matches every command (allSubstringsPresent
	// returns true for an empty needle set), which would let the first such rule
	// swallow every probe invocation and misattribute its canned response. Reject it
	// at load so a malformed fixture fails loud instead of silently shadowing later rules.
	for i, rule := range fx.Runs {
		if len(rule.Match) == 0 {
			t.Fatalf("probe fixture %s: runs[%d] has an empty match (would match every command)", path, i)
		}
	}
	return fx
}

// loadContainmentExpect reads and parses a *.expect.json fixture. Fail-closed:
// any read/parse error or an empty probe set fails the test.
func loadContainmentExpect(t *testing.T, path string) containmentExpectFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read expect fixture %s: %v", path, err)
	}
	var fx containmentExpectFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse expect fixture %s: %v", path, err)
	}
	if len(fx.Probes) == 0 {
		t.Fatalf("expect fixture %s lists no probes", path)
	}
	if err := validateContainmentExpect(fx); err != nil {
		t.Fatalf("invalid expect fixture %s: %v", path, err)
	}
	return fx
}

func validateContainmentExpect(fx containmentExpectFixture) error {
	switch fx.ExitCode {
	case contain.ConformanceExitOK, contain.ConformanceExitFail, contain.ConformanceExitSkip:
	default:
		return fmt.Errorf("exit_code = %d, want one of 0, 1, 2", fx.ExitCode)
	}
	if len(fx.Probes) != len(expectedContainmentProbes) {
		return fmt.Errorf("lists %d probes, want exactly %d", len(fx.Probes), len(expectedContainmentProbes))
	}
	seen := make(map[int]struct{}, len(fx.Probes))
	for i, p := range fx.Probes {
		wantName, ok := expectedContainmentProbes[p.Probe]
		if !ok {
			return fmt.Errorf("probes[%d] has unexpected probe %d", i, p.Probe)
		}
		if _, ok := seen[p.Probe]; ok {
			return fmt.Errorf("probes[%d] duplicates probe %d", i, p.Probe)
		}
		seen[p.Probe] = struct{}{}
		if p.Name != wantName {
			return fmt.Errorf("probes[%d] name = %q, want %q", i, p.Name, wantName)
		}
		if !isContainmentStatus(p.Status) {
			return fmt.Errorf("probes[%d] status = %q, want pass/fail/skip", i, p.Status)
		}
	}
	for probe := range expectedContainmentProbes {
		if _, ok := seen[probe]; !ok {
			return fmt.Errorf("missing expected probe %d", probe)
		}
	}
	return nil
}

func isContainmentStatus(status string) bool {
	switch status {
	case contain.ConformanceStatusPass, contain.ConformanceStatusFail, contain.ConformanceStatusSkip:
		return true
	default:
		return false
	}
}

type auditedCannedRunner struct {
	rules []containmentRunRule
	calls []ruleMatchAudit
}

type ruleMatchAudit struct {
	cmdline string
	matches []int
}

// newAuditedCannedRunner builds the injected command runner from a fixture's
// run rules and records which rules matched each command. The harness later
// rejects zero-match, multi-match, and unused-rule fixtures so malformed
// fixtures cannot be blessed by a matching .expect.json.
func newAuditedCannedRunner(fx containmentProbeFixture) *auditedCannedRunner {
	return &auditedCannedRunner{rules: fx.Runs}
}

func (r *auditedCannedRunner) Run(_ context.Context, name string, args ...string) (string, int, error) {
	joined := name + " " + strings.Join(args, " ")
	var matches []int
	for i, rule := range r.rules {
		if allSubstringsPresent(joined, rule.Match) {
			matches = append(matches, i)
		}
	}
	r.calls = append(r.calls, ruleMatchAudit{cmdline: joined, matches: append([]int(nil), matches...)})

	switch len(matches) {
	case 0:
		return "", -1, errNoMatchingRule(joined)
	case 1:
		rule := r.rules[matches[0]]
		return rule.Stdout, rule.ExitCode, nil
	default:
		return "", -1, errAmbiguousMatchingRule(joined, matches)
	}
}

func (r *auditedCannedRunner) validate() error {
	used := make([]bool, len(r.rules))
	for _, call := range r.calls {
		switch len(call.matches) {
		case 0:
			return errNoMatchingRule(call.cmdline)
		case 1:
			used[call.matches[0]] = true
		default:
			return errAmbiguousMatchingRule(call.cmdline, call.matches)
		}
	}
	for i, ok := range used {
		if !ok {
			return fmt.Errorf("unused canned rule at runs[%d] with match %q", i, r.rules[i].Match)
		}
	}
	return nil
}

func allSubstringsPresent(haystack string, needles []string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}

type noMatchingRuleError string

func (e noMatchingRuleError) Error() string {
	return "no canned rule matched command line: " + string(e)
}

func errNoMatchingRule(cmdline string) error { return noMatchingRuleError(cmdline) }

type ambiguousMatchingRuleError struct {
	cmdline string
	matches []int
}

func (e ambiguousMatchingRuleError) Error() string {
	return fmt.Sprintf("ambiguous canned rules matched command line %q: run indexes %v", e.cmdline, e.matches)
}

func errAmbiguousMatchingRule(cmdline string, matches []int) error {
	return ambiguousMatchingRuleError{cmdline: cmdline, matches: append([]int(nil), matches...)}
}

// runContainmentFixture loads a fixture pair, drives the containment probes
// through the exported seam, and returns the results plus exit code.
func runContainmentFixture(t *testing.T, name string) ([]contain.ConformanceProbeResult, int) {
	t.Helper()
	probeFx := loadContainmentProbe(t, filepath.Join(containmentFixtureDir, name+".probe.json"))
	runner := newAuditedCannedRunner(probeFx)
	env := contain.ConformanceEnv{
		RunCommand:   runner.Run,
		AgentUser:    probeFx.AgentUser,
		OperatorUser: probeFx.OperatorUser,
	}
	results, exit, err := contain.RunContainmentConformance(context.Background(), env)
	if err != nil {
		t.Fatalf("RunContainmentConformance(%s): unexpected error: %v", name, err)
	}
	if err := runner.validate(); err != nil {
		t.Fatalf("%s: invalid canned command-runner fixture: %v", name, err)
	}
	return results, exit
}

// assertMatchesExpect checks per-probe status and aggregate exit code against
// the .expect.json contract.
func assertMatchesExpect(t *testing.T, name string, results []contain.ConformanceProbeResult, exit int) {
	t.Helper()
	expect := loadContainmentExpect(t, filepath.Join(containmentFixtureDir, name+".expect.json"))

	if exit != expect.ExitCode {
		t.Errorf("%s: exit code = %d, want %d", name, exit, expect.ExitCode)
	}
	if len(results) != len(expect.Probes) {
		t.Fatalf("%s: got %d probe results, want %d", name, len(results), len(expect.Probes))
	}
	byProbe := make(map[int]contain.ConformanceProbeResult, len(results))
	for _, r := range results {
		byProbe[r.Probe] = r
	}
	for _, want := range expect.Probes {
		got, ok := byProbe[want.Probe]
		if !ok {
			t.Errorf("%s: probe %d missing from results", name, want.Probe)
			continue
		}
		if got.Name != want.Name {
			t.Errorf("%s: probe %d name = %q, want %q", name, want.Probe, got.Name, want.Name)
		}
		if got.Status != want.Status {
			t.Errorf("%s: probe %d status = %q, want %q (detail: %s)", name, want.Probe, got.Status, want.Status, got.Detail)
		}
	}
}

// TestContainmentConformance drives every containment fixture pair under
// testdata/containment/ and asserts it matches its .expect.json.
func TestContainmentConformance(t *testing.T) {
	t.Parallel()

	fixtures := discoverContainmentFixtures(t)
	if len(fixtures) == 0 {
		t.Fatalf("no containment fixtures discovered under %s (fail-closed: empty corpus is never a pass)", containmentFixtureDir)
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			results, exit := runContainmentFixture(t, name)
			assertMatchesExpect(t, name, results, exit)
		})
	}
}

// TestContainmentConformance_LeakyEgressMustFail is the regression assertion:
// when the agent's direct-egress canary succeeds (curl exit 0), probe 8 MUST
// report fail and the aggregate MUST be a non-zero exit. If this property ever
// regresses, the egress-denied test is not real and CI must go red here.
func TestContainmentConformance_LeakyEgressMustFail(t *testing.T) {
	t.Parallel()

	results, exit := runContainmentFixture(t, "leaky-egress")

	if exit == contain.ConformanceExitOK {
		t.Fatalf("leaky-egress: aggregate exit = 0 (pass), but a leaked agent egress MUST fail the gate")
	}
	if exit != contain.ConformanceExitFail {
		t.Errorf("leaky-egress: aggregate exit = %d, want %d (fail)", exit, contain.ConformanceExitFail)
	}

	var probe8 contain.ConformanceProbeResult
	var found bool
	for _, r := range results {
		if r.Probe == 8 {
			probe8 = r
			found = true
		}
	}
	if !found {
		t.Fatalf("leaky-egress: probe 8 missing from results")
	}
	if probe8.Status != contain.ConformanceStatusFail {
		t.Errorf("leaky-egress: probe 8 status = %q, want %q — agent egress leak was not detected", probe8.Status, contain.ConformanceStatusFail)
	}
}

// TestContainmentConformance_PassAllIsClean asserts the clean baseline reports
// every probe pass with a 0 exit. A gate where the clean fixture cannot pass is
// as broken as one where the leaky fixture cannot fail.
func TestContainmentConformance_PassAllIsClean(t *testing.T) {
	t.Parallel()

	results, exit := runContainmentFixture(t, "pass-all")
	if exit != contain.ConformanceExitOK {
		t.Errorf("pass-all: aggregate exit = %d, want 0", exit)
	}
	for _, r := range results {
		if r.Status != contain.ConformanceStatusPass {
			t.Errorf("pass-all: probe %d (%s) status = %q, want pass (detail: %s)", r.Probe, r.Name, r.Status, r.Detail)
		}
	}
}

// TestContainmentConformance_NilRunnerFailsClosed asserts a misconfigured env
// (no runner) returns an error and a non-OK exit rather than silently passing.
func TestContainmentConformance_NilRunnerFailsClosed(t *testing.T) {
	t.Parallel()

	results, exit, err := contain.RunContainmentConformance(context.Background(), contain.ConformanceEnv{})
	if err == nil {
		t.Fatalf("nil runner: expected error, got nil (exit=%d, results=%v)", exit, results)
	}
	if exit == contain.ConformanceExitOK {
		t.Errorf("nil runner: exit = 0 (pass), want non-zero fail-closed exit")
	}
}

func TestContainmentConformance_InvalidExpectFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		expect  containmentExpectFixture
		wantErr string
	}{
		{
			name: "duplicate probe omits probe nine",
			expect: containmentExpectFixture{
				ExitCode: contain.ConformanceExitOK,
				Probes: []containmentExpectProbe{
					{Probe: 8, Name: "cc_agent_egress_denied", Status: "pass"},
					{Probe: 8, Name: "cc_agent_egress_denied", Status: "pass"},
				},
			},
			wantErr: "duplicates probe 8",
		},
		{
			name: "unknown status",
			expect: containmentExpectFixture{
				ExitCode: contain.ConformanceExitOK,
				Probes: []containmentExpectProbe{
					{Probe: 8, Name: "cc_agent_egress_denied", Status: "pass"},
					{Probe: 9, Name: "operator_egress_reachable", Status: "maybe"},
				},
			},
			wantErr: "want pass/fail/skip",
		},
		{
			name: "unexpected exit code",
			expect: containmentExpectFixture{
				ExitCode: 99,
				Probes: []containmentExpectProbe{
					{Probe: 8, Name: "cc_agent_egress_denied", Status: "pass"},
					{Probe: 9, Name: "operator_egress_reachable", Status: "pass"},
				},
			},
			wantErr: "want one of 0, 1, 2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateContainmentExpect(tc.expect)
			if err == nil {
				t.Fatalf("expected invalid expect fixture error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("invalid expect fixture error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestContainmentConformance_InvalidRunRulesFailClosed(t *testing.T) {
	t.Parallel()

	baseRuns := []containmentRunRule{
		{Match: []string{"sudo", "pipelock-agent", "/usr/bin/curl"}, Stdout: "200", ExitCode: 0},
		{Match: []string{"sudo", "operator", "/usr/bin/curl"}, Stdout: "200", ExitCode: 0},
	}
	tests := []struct {
		name    string
		runs    []containmentRunRule
		wantErr string
	}{
		{
			name: "missing operator rule",
			runs: []containmentRunRule{
				baseRuns[0],
			},
			wantErr: "no canned rule matched command line",
		},
		{
			name: "ambiguous duplicate rule",
			runs: []containmentRunRule{
				baseRuns[0],
				baseRuns[0],
				baseRuns[1],
			},
			wantErr: "ambiguous canned rules matched command line",
		},
		{
			name: "unused stale rule",
			runs: []containmentRunRule{
				baseRuns[0],
				baseRuns[1],
				{Match: []string{"never-used-command"}, Stdout: "200", ExitCode: 0},
			},
			wantErr: "unused canned rule",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runner := newAuditedCannedRunner(containmentProbeFixture{
				AgentUser:    "pipelock-agent",
				OperatorUser: "operator",
				Runs:         tc.runs,
			})
			_, _, err := contain.RunContainmentConformance(context.Background(), contain.ConformanceEnv{
				RunCommand:   runner.Run,
				AgentUser:    "pipelock-agent",
				OperatorUser: "operator",
			})
			if err != nil {
				t.Fatalf("RunContainmentConformance returned unexpected setup error: %v", err)
			}
			err = runner.validate()
			if err == nil {
				t.Fatalf("expected invalid rule set error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("invalid rule set error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// discoverContainmentFixtures lists fixture base names (those with both a
// .probe.json and a .expect.json) under the fixture directory.
func discoverContainmentFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(containmentFixtureDir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", containmentFixtureDir, err)
	}
	var names []string
	probes := map[string]struct{}{}
	expects := map[string]struct{}{}
	for _, e := range entries {
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ".probe.json"):
			base := strings.TrimSuffix(n, ".probe.json")
			probes[base] = struct{}{}
			expectPath := filepath.Join(containmentFixtureDir, base+".expect.json")
			if _, err := os.Stat(expectPath); err != nil {
				t.Fatalf("fixture %s has no matching .expect.json (%s): %v", base, expectPath, err)
			}
			names = append(names, base)
		case strings.HasSuffix(n, ".expect.json"):
			expects[strings.TrimSuffix(n, ".expect.json")] = struct{}{}
		default:
			continue
		}
	}
	for base := range expects {
		if _, ok := probes[base]; !ok {
			t.Fatalf("expect fixture %s.expect.json has no matching .probe.json", base)
		}
	}
	return names
}
