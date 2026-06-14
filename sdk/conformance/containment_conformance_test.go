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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain"
)

const containmentFixtureDir = "testdata/containment"

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
	return fx
}

// cannedRunner builds the injected command runner from a fixture's run rules.
// It returns a non-nil error when no rule matches so a fixture that forgets a
// rule fails loud (the probe surfaces that as skip, which the gate treats as a
// non-pass) rather than silently passing.
func cannedRunner(fx containmentProbeFixture) contain.ConformanceRunCommand {
	return func(_ context.Context, name string, args ...string) (string, int, error) {
		joined := name + " " + strings.Join(args, " ")
		for _, rule := range fx.Runs {
			if allSubstringsPresent(joined, rule.Match) {
				return rule.Stdout, rule.ExitCode, nil
			}
		}
		return "", -1, errNoMatchingRule(joined)
	}
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

// runContainmentFixture loads a fixture pair, drives the containment probes
// through the exported seam, and returns the results plus exit code.
func runContainmentFixture(t *testing.T, name string) ([]contain.ConformanceProbeResult, int) {
	t.Helper()
	probeFx := loadContainmentProbe(t, filepath.Join(containmentFixtureDir, name+".probe.json"))
	env := contain.ConformanceEnv{
		RunCommand:   cannedRunner(probeFx),
		AgentUser:    probeFx.AgentUser,
		OperatorUser: probeFx.OperatorUser,
	}
	results, exit, err := contain.RunContainmentConformance(context.Background(), env)
	if err != nil {
		t.Fatalf("RunContainmentConformance(%s): unexpected error: %v", name, err)
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

// discoverContainmentFixtures lists fixture base names (those with both a
// .probe.json and a .expect.json) under the fixture directory.
func discoverContainmentFixtures(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(containmentFixtureDir)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", containmentFixtureDir, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".probe.json") {
			continue
		}
		base := strings.TrimSuffix(n, ".probe.json")
		expectPath := filepath.Join(containmentFixtureDir, base+".expect.json")
		if _, err := os.Stat(expectPath); err != nil {
			t.Fatalf("fixture %s has no matching .expect.json (%s): %v", base, expectPath, err)
		}
		names = append(names, base)
	}
	return names
}
