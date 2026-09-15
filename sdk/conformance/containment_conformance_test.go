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
	"errors"
	"fmt"
	"io"
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
	Comment  string   `json:"comment"`
	Match    []string `json:"match"`
	Stdout   string   `json:"stdout"`
	ExitCode int      `json:"exit_code"`
}

// containmentProbeFixture is the parsed *.probe.json input.
//
// NFTChainText, AgentUID, ProxyUID, OperatorUID, and ProxyPort are an
// alternative to DropCounterReads: instead of pre-baking
// probe 8's before/after DROP-counter values, a fixture supplies the literal
// `nft -n -a list chain ...` output text and lets production's own chain-text
// recognizer (agentUIDBareAcceptBeforeDrop,
// chainLinesHaveUnsafeVerdictBeforeAgentDrop) classify it. This is what makes
// the agent-accept-before-drop structural containment hole fixture possible:
// that outcome cannot be expressed as a pre-baked counter pair at all. The two
// input styles are mutually exclusive (see validateContainmentProbeFixture).
type containmentProbeFixture struct {
	Description      string               `json:"description"`
	AgentUser        string               `json:"agent_user"`
	OperatorUser     string               `json:"operator_user"`
	DropCounterReads []uint64             `json:"drop_counter_reads"`
	NFTChainText     string               `json:"nft_chain_text"`
	AgentUID         int                  `json:"agent_uid"`
	ProxyUID         int                  `json:"proxy_uid"`
	OperatorUID      int                  `json:"operator_uid"`
	ProxyPort        int                  `json:"proxy_port"`
	Runs             []containmentRunRule `json:"runs"`
}

const (
	defaultFixtureAgentUser = "pipelock-agent"
	fixtureCurlPath         = "/usr/bin/curl"
	directCanaryURL         = "http://192.0.2.1:9/"
	operatorCanaryURL       = "https://example.com/"
)

// containmentExpectProbe is one expected per-probe outcome.
type containmentExpectProbe struct {
	Probe  int    `json:"probe"`
	Name   string `json:"name"`
	Status string `json:"status"`
	// DetailContains is optional. When set, the probe's
	// detail string must contain it. This is what lets a fixture assert
	// WHICH production outcome produced a given status, distinguishing e.g.
	// the agent-accept-before-drop structural hole from a counter-based
	// leaked-egress failure even though both report status "fail". Absent in
	// the original two fixtures, whose comparison is unchanged.
	DetailContains string `json:"detail_contains,omitempty"`
}

// containmentExpectFixture is the parsed *.expect.json input.
type containmentExpectFixture struct {
	Description string                   `json:"description"`
	ExitCode    int                      `json:"exit_code"`
	Probes      []containmentExpectProbe `json:"probes"`
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
	// DisallowUnknownFields makes an unrecognized field
	// fail loud at load instead of being silently ignored: a schema-widening
	// mistake in a published fixture should never pass by accident, and
	// nothing in the current two fixtures nor the new one below sets a field
	// outside this struct, so this is a pure tightening with no behavior
	// change for them.
	if err := decodeFixtureDocument(data, &fx); err != nil {
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
	if err := validateContainmentProbeFixture(fx); err != nil {
		t.Fatalf("invalid probe fixture %s: %v", path, err)
	}
	return fx
}

// validateContainmentProbeFixture makes the canned runner prove the actual
// canary command contract, not merely that sudo/curl ran under two usernames.
// Without these exact anchors, a probe-8 regression back to the proxy-capable
// operator URL (or loss of --noproxy) could still match a broad fixture rule and
// let the standalone conformance gate report PASS.
func validateContainmentProbeFixture(fx containmentProbeFixture) error {
	agentUser := fx.AgentUser
	if agentUser == "" {
		agentUser = defaultFixtureAgentUser
	}
	directRequired := []string{
		"sudo -n -u " + agentUser + " -- " + fixtureCurlPath,
		"--connect-timeout 1",
		"--max-time 2",
		"--noproxy *",
		"PLK_TIME_CONNECT=%{time_connect}",
		directCanaryURL,
	}
	operatorInvocation := fixtureCurlPath
	if fx.OperatorUser != "" {
		operatorInvocation = "sudo -n -u " + fx.OperatorUser + " -- " + fixtureCurlPath
	}
	operatorRequired := []string{
		operatorInvocation,
		"--connect-timeout 3",
		"--max-time 5",
		"--noproxy *",
		operatorCanaryURL,
	}

	if matches := countRulesWithExactAnchors(fx.Runs, directRequired); matches != 1 {
		return fmt.Errorf("has %d exact probe-8 command rule(s), want 1 with match anchors %q", matches, directRequired)
	}
	if matches := countRulesWithExactAnchors(fx.Runs, operatorRequired); matches != 1 {
		return fmt.Errorf("has %d exact probe-9 command rule(s), want 1 with match anchors %q", matches, operatorRequired)
	}

	usesChainText := fx.NFTChainText != ""
	usesRawCounters := len(fx.DropCounterReads) > 0
	if usesChainText && usesRawCounters {
		return errors.New("sets both nft_chain_text and drop_counter_reads; these are mutually exclusive fixture inputs (ambiguous)")
	}
	if usesChainText && (fx.AgentUID <= 0 || fx.ProxyUID <= 0) {
		return errors.New("nft_chain_text requires positive agent_uid and proxy_uid")
	}
	if usesChainText && fx.AgentUID == fx.ProxyUID {
		return errors.New("agent_uid and proxy_uid must be distinct")
	}
	if usesChainText && fx.OperatorUID < 0 {
		return errors.New("operator_uid must be zero (unknown) or positive")
	}
	if usesChainText && fx.OperatorUID != 0 && (fx.OperatorUID == fx.AgentUID || fx.OperatorUID == fx.ProxyUID) {
		return errors.New("operator_uid must be distinct from agent_uid and proxy_uid")
	}
	if usesChainText && fx.ProxyPort != 0 && (fx.ProxyPort < 1 || fx.ProxyPort > 65535) {
		return errors.New("proxy_port must be between 1 and 65535")
	}
	// A UID/port field set without nft_chain_text is dead: nothing reads it,
	// and the fixture would silently claim an input it does not actually
	// drive. Reject it the same way an unused canned run rule is rejected.
	if !usesChainText && (fx.AgentUID != 0 || fx.ProxyUID != 0 || fx.OperatorUID != 0 || fx.ProxyPort != 0) {
		return errors.New("agent_uid, proxy_uid, operator_uid, and proxy_port have no effect without nft_chain_text")
	}
	return nil
}

func countRulesWithExactAnchors(rules []containmentRunRule, required []string) int {
	matches := 0
	for _, rule := range rules {
		if containsAllExact(rule.Match, required) {
			matches++
		}
	}
	return matches
}

func containsAllExact(got, required []string) bool {
	for _, want := range required {
		found := false
		for _, value := range got {
			if value == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
	if err := decodeFixtureDocument(data, &fx); err != nil {
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
			return fmt.Errorf("probes[%d] status = %q, want pass/fail/skip/unknown", i, p.Status)
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
	case contain.ConformanceStatusPass, contain.ConformanceStatusFail, contain.ConformanceStatusSkip, contain.ConformanceStatusUnknown:
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
		DropCounter:  fixtureDropCounter(probeFx.DropCounterReads),
		NFTChainText: probeFx.NFTChainText,
		AgentUID:     probeFx.AgentUID,
		ProxyUID:     probeFx.ProxyUID,
		OperatorUID:  probeFx.OperatorUID,
		ProxyPort:    probeFx.ProxyPort,
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

func fixtureDropCounter(values []uint64) contain.ConformanceDropCounter {
	if len(values) == 0 {
		return nil
	}
	next := 0
	return func(context.Context) (uint64, error) {
		if next >= len(values) {
			return 0, fmt.Errorf("DROP counter fixture exhausted after %d read(s)", next)
		}
		value := values[next]
		next++
		return value, nil
	}
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
		if want.DetailContains != "" && !strings.Contains(got.Detail, want.DetailContains) {
			t.Errorf("%s: probe %d detail = %q, want it to contain %q", name, want.Probe, got.Detail, want.DetailContains)
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

func TestValidateContainmentProbeFixtureRequiresExactCanaryCommands(t *testing.T) {
	t.Parallel()

	directRule := containmentRunRule{Match: []string{
		"sudo -n -u pipelock-agent -- /usr/bin/curl",
		"--connect-timeout 1",
		"--max-time 2",
		"--noproxy *",
		"PLK_TIME_CONNECT=%{time_connect}",
		directCanaryURL,
	}}
	operatorRule := containmentRunRule{Match: []string{
		"sudo -n -u operator -- /usr/bin/curl",
		"--connect-timeout 3",
		"--max-time 5",
		"--noproxy *",
		operatorCanaryURL,
	}}
	valid := containmentProbeFixture{
		AgentUser:    defaultFixtureAgentUser,
		OperatorUser: "operator",
		Runs:         []containmentRunRule{directRule, operatorRule},
	}
	if err := validateContainmentProbeFixture(valid); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*containmentProbeFixture)
		wantErr string
	}{
		{
			name: "broad username-only agent rule",
			mutate: func(fx *containmentProbeFixture) {
				fx.Runs[0].Match = []string{"sudo", "pipelock-agent", fixtureCurlPath}
			},
			wantErr: "exact probe-8 command",
		},
		{
			name: "agent rule missing no-proxy bypass",
			mutate: func(fx *containmentProbeFixture) {
				fx.Runs[0].Match = append([]string(nil), directRule.Match[:3]...)
				fx.Runs[0].Match = append(fx.Runs[0].Match, directCanaryURL)
			},
			wantErr: "exact probe-8 command",
		},
		{
			name: "agent rule points at operator canary",
			mutate: func(fx *containmentProbeFixture) {
				fx.Runs[0].Match = append([]string(nil), directRule.Match...)
				fx.Runs[0].Match[len(fx.Runs[0].Match)-1] = operatorCanaryURL
			},
			wantErr: "exact probe-8 command",
		},
		{
			name: "operator rule missing reachability URL",
			mutate: func(fx *containmentProbeFixture) {
				fx.Runs[1].Match = append([]string(nil), operatorRule.Match[:len(operatorRule.Match)-1]...)
			},
			wantErr: "exact probe-9 command",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := valid
			fx.Runs = append([]containmentRunRule(nil), valid.Runs...)
			tc.mutate(&fx)
			err := validateContainmentProbeFixture(fx)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
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

// baseChainTextFixtureRuns are the two mandatory run rules any probe fixture
// needs to pass validateContainmentProbeFixture's exact-anchor checks,
// reused by the nft_chain_text schema tests below so each test case only has
// to vary the field(s) it is actually exercising.
func baseChainTextFixtureRuns() []containmentRunRule {
	return []containmentRunRule{
		{
			Match:    []string{"sudo -n -u pipelock-agent -- /usr/bin/curl", "--connect-timeout 1", "--max-time 2", "--noproxy *", "PLK_TIME_CONNECT=%{time_connect}", directCanaryURL},
			Stdout:   "curl: (7) Failed to connect\nPLK_TIME_CONNECT=0.000000\n000",
			ExitCode: 7,
		},
		{
			Match:    []string{"sudo -n -u operator -- " + fixtureCurlPath, "--connect-timeout 3", "--max-time 5", "--noproxy *", operatorCanaryURL},
			Stdout:   "200",
			ExitCode: 0,
		},
	}
}

func validChainText() string {
	return "table inet pipelock_containment {\n  chain output_filter {\n    type filter hook output priority filter; policy accept;\n    meta skuid 1000 accept\n    meta skuid 988 accept\n    meta skuid 987 ip daddr 127.0.0.1 tcp dport 8888 accept\n    meta skuid 987 udp dport 53 counter packets 0 bytes 0 log prefix \"pipelock-contain class=direct_dns_blocked \" drop\n    meta skuid 987 tcp dport 53 counter packets 0 bytes 0 log prefix \"pipelock-contain class=direct_dns_blocked \" drop\n    meta skuid 987 counter packets 0 bytes 0 log prefix \"pipelock-contain class=not_routing_through_pipelock \" drop\n  }\n}\n"
}

// TestValidateContainmentProbeFixture_ChainTextSchema is the LOADER-level
// (fail-closed-at-load) counterpart to the runtime chain-text-recognizer
// tests in internal/cli/contain: it proves the *.probe.json schema itself
// rejects the ambiguous and under-specified shapes before the fixture is
// ever driven.
func TestValidateContainmentProbeFixture_ChainTextSchema(t *testing.T) {
	base := containmentProbeFixture{
		AgentUser:    "pipelock-agent",
		OperatorUser: "operator",
		Runs:         baseChainTextFixtureRuns(),
	}

	tests := []struct {
		name    string
		mutate  func(containmentProbeFixture) containmentProbeFixture
		wantErr string
	}{
		{
			name: "chain_text_and_drop_counter_reads_both_set",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID = 987, 988
				fx.DropCounterReads = []uint64{1, 2}
				return fx
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "chain_text_negative_agent_uid",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID = -987, 988
				return fx
			},
			wantErr: "requires positive agent_uid and proxy_uid",
		},
		{
			name: "chain_text_operator_uid_aliases_agent",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID, fx.OperatorUID = 987, 988, 987
				return fx
			},
			wantErr: "operator_uid must be distinct",
		},
		{
			name: "chain_text_negative_operator_uid",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID, fx.OperatorUID = 987, 988, -1
				return fx
			},
			wantErr: "operator_uid must be zero (unknown) or positive",
		},
		{
			name: "chain_text_proxy_port_out_of_range",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID, fx.ProxyPort = 987, 988, 70000
				return fx
			},
			wantErr: "proxy_port must be between 1 and 65535",
		},
		{
			name: "chain_text_missing_agent_uid",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.ProxyUID = 988
				return fx
			},
			wantErr: "requires positive agent_uid and proxy_uid",
		},
		{
			name: "chain_text_missing_proxy_uid",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID = 987
				return fx
			},
			wantErr: "requires positive agent_uid and proxy_uid",
		},
		{
			name: "chain_text_equal_uids",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID = 987, 987
				return fx
			},
			wantErr: "must be distinct",
		},
		{
			name: "uid_fields_without_chain_text_are_dead",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.AgentUID = 987
				return fx
			},
			wantErr: "have no effect without nft_chain_text",
		},
		{
			name: "proxy_port_without_chain_text_is_dead",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.ProxyPort = 9999
				return fx
			},
			wantErr: "have no effect without nft_chain_text",
		},
		{
			name: "valid_chain_text_fixture_passes",
			mutate: func(fx containmentProbeFixture) containmentProbeFixture {
				fx.NFTChainText = validChainText()
				fx.AgentUID, fx.ProxyUID, fx.OperatorUID, fx.ProxyPort = 987, 988, 1000, 8888
				return fx
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateContainmentProbeFixture(tc.mutate(base))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a validation error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validation error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestLoadContainmentProbe_RejectsUnknownField proves the *.probe.json loader
// fails closed on a field outside the published schema instead of silently
// ignoring it, guarding against a fixture accidentally widening the contract.
func TestLoadContainmentProbe_RejectsUnknownField(t *testing.T) {
	body := `{
		"agent_user": "pipelock-agent",
		"operator_user": "operator",
		"not_a_real_field": true,
		"runs": []
	}`
	var fx containmentProbeFixture
	err := decodeFixtureDocument([]byte(body), &fx)
	if err == nil {
		t.Fatal("decode: expected an error on an unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decode error = %q, want it to mention the unknown field", err.Error())
	}
}

// TestLoadContainmentProbe_MalformedChainTextIsRejectedAtRuntime documents
// (and proves) that a fixture whose nft_chain_text the recognizer cannot
// parse is NOT a load-time schema violation the way an ambiguous or
// under-specified UID combination is: attributedNFTChainLines' parse error
// surfaces as probe 8's beforeErr and resolves to UNKNOWN, never to a silent
// PASS. The runtime, per-recognizer-branch proof lives in
// internal/cli/contain: TestRunContainmentConformance_MalformedChainTextFailsClosed.
// This test is the schema-loader-level companion: the LOADER accepts the
// fixture (chain-text syntax is not a load-time-checkable property without
// duplicating the unexported recognizer), and the runtime result is the
// fail-closed backstop.
func TestLoadContainmentProbe_MalformedChainTextIsRejectedAtRuntime(t *testing.T) {
	fx := containmentProbeFixture{
		AgentUser:    "pipelock-agent",
		OperatorUser: "operator",
		NFTChainText: "this is not valid nft chain output",
		AgentUID:     987,
		ProxyUID:     988,
		Runs:         baseChainTextFixtureRuns(),
	}
	if err := validateContainmentProbeFixture(fx); err != nil {
		t.Fatalf("unexpected schema-level validation error for malformed-but-well-formed-schema chain text: %v", err)
	}
	runner := newAuditedCannedRunner(fx)
	results, exit, err := contain.RunContainmentConformance(context.Background(), contain.ConformanceEnv{
		RunCommand:   runner.Run,
		AgentUser:    fx.AgentUser,
		OperatorUser: fx.OperatorUser,
		NFTChainText: fx.NFTChainText,
		AgentUID:     fx.AgentUID,
		ProxyUID:     fx.ProxyUID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exit != contain.ConformanceExitSkip {
		t.Fatalf("malformed chain text must resolve to the inconclusive exit code %d, got %d", contain.ConformanceExitSkip, exit)
	}
	var probe8 *contain.ConformanceProbeResult
	for i := range results {
		if results[i].Probe == 8 {
			probe8 = &results[i]
		}
	}
	if probe8 == nil {
		t.Fatal("probe 8 missing from results")
	}
	if probe8.Status != contain.ConformanceStatusUnknown {
		t.Fatalf("malformed chain text must resolve to UNKNOWN, got status %q detail %q", probe8.Status, probe8.Detail)
	}
	if !strings.Contains(probe8.Detail, "read DROP counter before probe") {
		t.Fatalf("probe 8 detail = %q, want the parser error surfaced as the before-probe counter read", probe8.Detail)
	}
}

// decodeFixtureDocument decodes exactly one JSON document into v with
// unknown fields rejected. DisallowUnknownFields only polices members of the
// first object; a valid fixture followed by a second JSON value would
// otherwise load silently, which contradicts the artifact's claim that
// out-of-schema fixture content fails loudly, so anything other than
// whitespace after the first document is an error too.
func decodeFixtureDocument(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing json.RawMessage
	err := dec.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("trailing content after the fixture document: %w", err)
	}
	return errors.New("a second JSON value follows the fixture document; a fixture is exactly one document")
}

// TestContainmentFixtureLoadersRejectTrailingJSON proves the loaders accept
// exactly one JSON document: a valid fixture followed by a second value must
// fail to decode, for both the probe and the expect shape, while the
// unmodified fixtures still decode.
func TestContainmentFixtureLoadersRejectTrailingJSON(t *testing.T) {
	dir := filepath.Join("testdata", "containment")
	cases := []struct {
		name string
		src  string
		into func() any
	}{
		{"probe", "pass-all.probe.json", func() any { return &containmentProbeFixture{} }},
		{"expect", "pass-all.expect.json", func() any { return &containmentExpectFixture{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, tc.src)))
			if err != nil {
				t.Fatalf("read %s: %v", tc.src, err)
			}
			if err := decodeFixtureDocument(data, tc.into()); err != nil {
				t.Fatalf("unmodified %s fixture must decode: %v", tc.name, err)
			}
			withSecond := append(append([]byte{}, data...), []byte("\n{\"description\": \"second document\"}\n")...)
			if err := decodeFixtureDocument(withSecond, tc.into()); err == nil {
				t.Fatalf("%s loader accepted a fixture followed by a second JSON document", tc.name)
			}
			withGarbage := append(append([]byte{}, data...), []byte("\ntrailing garbage\n")...)
			if err := decodeFixtureDocument(withGarbage, tc.into()); err == nil {
				t.Fatalf("%s loader accepted a fixture followed by non-JSON text", tc.name)
			}
		})
	}
}
