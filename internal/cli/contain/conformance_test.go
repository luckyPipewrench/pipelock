// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// cannedResp is one canned (stdout, exitCode, err) the injected runner returns.
type cannedResp struct {
	out  string
	code int
	err  error
}

// conformanceRunner dispatches on the executable name: probe 8 shells out via
// "sudo", and probe 9 (with an empty OperatorUser) invokes curl directly, so
// the command name alone tells the two egress probes apart.
func conformanceRunner(probe8, probe9 cannedResp) ConformanceRunCommand {
	return func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "sudo" {
			return probe8.out, probe8.code, probe8.err
		}
		return probe9.out, probe9.code, probe9.err
	}
}

func conformanceDropCounters(values ...uint64) ConformanceDropCounter {
	next := 0
	return func(context.Context) (uint64, error) {
		if next >= len(values) {
			return 0, errors.New("canned DROP counter exhausted")
		}
		value := values[next]
		next++
		return value, nil
	}
}

func TestRunContainmentConformance_NilRunnerFailsClosed(t *testing.T) {
	results, exit, err := RunContainmentConformance(context.Background(), ConformanceEnv{})
	if err == nil {
		t.Fatal("nil runner: expected a fail-closed error, got nil")
	}
	if results != nil {
		t.Fatalf("nil runner: expected nil results, got %v", results)
	}
	if exit != conformanceExitInvalid {
		t.Fatalf("nil runner: exit = %d, want %d (invalid/config)", exit, conformanceExitInvalid)
	}
}

func TestRunContainmentConformance_Outcomes(t *testing.T) {
	const blockedExit = 7 // curl connection-refused style exit when egress is denied

	tests := []struct {
		name       string
		ctx        context.Context
		agentUser  string
		probe8     cannedResp // sudo -u agent -- curl
		probe9     cannedResp // curl (operator, empty user -> direct)
		wantExit   int
		dropCounts []uint64
		wantStatus map[int]string // probe number -> expected status
	}{
		{
			name:       "both_pass_nil_ctx_default_agent_user",
			ctx:        nil, // exercises the ctx == nil default
			agentUser:  "",  // exercises the defaultAgentUser fallback
			probe8:     cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: blockedExit},
			probe9:     cannedResp{out: "200", code: 0},
			dropCounts: []uint64{12, 13},
			wantExit:   ConformanceExitOK,
			wantStatus: map[int]string{
				8: ConformanceStatusPass,
				9: ConformanceStatusPass,
			},
		},
		{
			name:      "blocked_curl_without_counter_is_unknown",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: blockedExit},
			probe9:    cannedResp{out: "200", code: 0},
			wantExit:  ConformanceExitSkip,
			wantStatus: map[int]string{
				8: ConformanceStatusUnknown,
				9: ConformanceStatusPass,
			},
		},
		{
			name:      "agent_egress_leaked_fails",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{out: "200", code: 0}, // agent reached the internet -> leak
			probe9:    cannedResp{out: "200", code: 0},
			wantExit:  ConformanceExitFail,
			wantStatus: map[int]string{
				8: ConformanceStatusFail,
				9: ConformanceStatusPass,
			},
		},
		{
			name:      "agent_leak_overrides_operator_skip",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{out: "200", code: 0},
			probe9:    cannedResp{err: errors.New("curl unavailable")},
			wantExit:  ConformanceExitFail,
			wantStatus: map[int]string{
				8: ConformanceStatusFail,
				9: ConformanceStatusSkip,
			},
		},
		{
			name:      "operator_failure_overrides_unknown_agent_attribution",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: blockedExit},
			probe9:    cannedResp{out: "curl: (22) HTTP 500", code: 22},
			wantExit:  ConformanceExitFail,
			wantStatus: map[int]string{
				8: ConformanceStatusUnknown,
				9: ConformanceStatusFail,
			},
		},
		{
			name:      "runner_unavailable_skips",
			ctx:       context.Background(),
			agentUser: "pipelock-agent",
			probe8:    cannedResp{err: errors.New("sudo: command not found")},
			probe9:    cannedResp{err: errors.New("curl: command not found")},
			wantExit:  ConformanceExitSkip,
			wantStatus: map[int]string{
				8: ConformanceStatusSkip,
				9: ConformanceStatusSkip,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := ConformanceEnv{
				RunCommand: conformanceRunner(tc.probe8, tc.probe9),
				AgentUser:  tc.agentUser,
			}
			if tc.dropCounts != nil {
				env.DropCounter = conformanceDropCounters(tc.dropCounts...)
			}
			results, exit, err := RunContainmentConformance(tc.ctx, env)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if exit != tc.wantExit {
				t.Fatalf("exit = %d, want %d", exit, tc.wantExit)
			}
			if len(results) != len(tc.wantStatus) {
				t.Fatalf("got %d results, want %d", len(results), len(tc.wantStatus))
			}
			for _, r := range results {
				want, ok := tc.wantStatus[r.Probe]
				if !ok {
					t.Fatalf("unexpected probe %d in results", r.Probe)
				}
				if r.Status != want {
					t.Errorf("probe %d (%s): status = %q, want %q (detail: %s)", r.Probe, r.Name, r.Status, want, r.Detail)
				}
			}
		})
	}
}

// containmentChainText builds a synthetic `nft -n -a list chain inet <table>
// <chain>` output for the conformance chain-text recognizer tests. extra, when
// non-empty, is inserted right after the two managed accepts and before the
// loopback-allow rule (i.e., in the pre-drop region), so callers can inject an
// agent-UID bare-accept bypass line at exactly the position production would
// see one.
func containmentChainText(operatorUID, proxyUID, agentUID, port int, extra string) string {
	extraLine := ""
	if extra != "" {
		extraLine = "\t\t" + extra + "\n"
	}
	return "table inet " + defaultNFTTable + " {\n" +
		"\tchain " + defaultNFTChain + " {\n" +
		"\t\ttype filter hook output priority filter; policy accept;\n" +
		"\t\tmeta skuid " + itoa(operatorUID) + " accept\n" +
		"\t\tmeta skuid " + itoa(proxyUID) + " accept\n" +
		extraLine +
		"\t\tmeta skuid " + itoa(agentUID) + " ip daddr 127.0.0.1 tcp dport " + itoa(port) + " accept\n" +
		"\t\tmeta skuid " + itoa(agentUID) + " udp dport 53 counter packets 0 bytes 0 log prefix \"" + nftLogPrefix(EgressClassDirectDNS) + " \" drop\n" +
		"\t\tmeta skuid " + itoa(agentUID) + " tcp dport 53 counter packets 0 bytes 0 log prefix \"" + nftLogPrefix(EgressClassDirectDNS) + " \" drop\n" +
		"\t\tmeta skuid " + itoa(agentUID) + " counter packets 9 bytes 900 log prefix \"" + nftLogPrefix(EgressClassNotRoutingThroughPipelock) + " \" drop\n" +
		"\t}\n" +
		"}\n"
}

func TestRunContainmentConformance_ChainTextAndDropCounterAmbiguous(t *testing.T) {
	env := ConformanceEnv{
		RunCommand:   conformanceRunner(cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7}, cannedResp{out: "200", code: 0}),
		NFTChainText: containmentChainText(1000, 988, 987, defaultProxyPort, ""),
		AgentUID:     987,
		ProxyUID:     988,
		DropCounter:  conformanceDropCounters(1, 2),
	}
	_, exit, err := RunContainmentConformance(context.Background(), env)
	if err == nil {
		t.Fatal("NFTChainText + DropCounter: expected an ambiguous-input error, got nil")
	}
	if exit != conformanceExitInvalid {
		t.Fatalf("exit = %d, want %d (invalid/config)", exit, conformanceExitInvalid)
	}
}

func TestRunContainmentConformance_ChainTextRequiresUIDs(t *testing.T) {
	tests := []struct {
		name     string
		agentUID int
		proxyUID int
	}{
		{"missing_agent_uid", 0, 988},
		{"missing_proxy_uid", 987, 0},
		{"equal_uids", 987, 987},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := ConformanceEnv{
				RunCommand:   conformanceRunner(cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7}, cannedResp{out: "200", code: 0}),
				NFTChainText: containmentChainText(1000, 988, 987, defaultProxyPort, ""),
				AgentUID:     tc.agentUID,
				ProxyUID:     tc.proxyUID,
			}
			_, exit, err := RunContainmentConformance(context.Background(), env)
			if err == nil {
				t.Fatalf("%s: expected a fail-closed error, got nil", tc.name)
			}
			if exit != conformanceExitInvalid {
				t.Fatalf("%s: exit = %d, want %d (invalid/config)", tc.name, exit, conformanceExitInvalid)
			}
		})
	}
}

// TestRunContainmentConformance_ChainTextReachesRealRecognizer is the
// non-vacuity proof that NFTChainText drives probe 8 through the SAME
// recognizer production uses (agentUIDBareAcceptBeforeDrop and
// chainLinesHaveUnsafeVerdictBeforeAgentDrop), not a fixture-side
// reimplementation of it.
func TestRunContainmentConformance_ChainTextReachesRealRecognizer(t *testing.T) {
	const (
		operatorUID = 1000
		proxyUID    = 988
		agentUID    = 987
	)
	tests := []struct {
		name       string
		extra      string
		curl8      cannedResp
		wantStatus string
		wantDetail string
	}{
		// NFTChainText is a single static text read for both the before and
		// after counter samples, so a clean chain (no bypass, no unsafe
		// verdict) never shows a counter delta and stays UNKNOWN rather than
		// PASS. That is the correct, honest outcome for a static fixture: a
		// PASS baseline is exercised by drop_counter_reads instead (see the
		// pass-all fixture), and this recognizer path exists to prove the
		// structural/unsafe-verdict FAIL and UNKNOWN branches, not PASS.
		{
			name:       "clean_chain_is_unknown_not_pass_without_a_counter_delta",
			extra:      "",
			curl8:      cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7},
			wantStatus: ConformanceStatusUnknown,
			wantDetail: "managed DROP counter did not increase",
		},
		{
			name:       "agent_bare_accept_before_drop_is_structural_hole",
			extra:      `meta skuid 987 accept comment "fixture: bare agent accept"`,
			curl8:      cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7},
			wantStatus: ConformanceStatusFail,
			wantDetail: "CONTAINMENT HOLE: agent UID accept rule bypasses managed catch-all DROP",
		},
		{
			name:       "unsafe_verdict_before_agent_drop_is_unattributable",
			extra:      "ip daddr 203.0.113.5 reject",
			curl8:      cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7},
			wantStatus: ConformanceStatusUnknown,
			wantDetail: "unexpected verdict before managed catch-all DROP",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := ConformanceEnv{
				RunCommand:   conformanceRunner(tc.curl8, cannedResp{out: "200", code: 0}),
				NFTChainText: containmentChainText(operatorUID, proxyUID, agentUID, defaultProxyPort, tc.extra),
				AgentUID:     agentUID,
				ProxyUID:     proxyUID,
				OperatorUID:  operatorUID,
			}
			results, _, err := RunContainmentConformance(context.Background(), env)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var probe8 ConformanceProbeResult
			for _, r := range results {
				if r.Probe == 8 {
					probe8 = r
				}
			}
			if probe8.Status != tc.wantStatus {
				t.Fatalf("probe 8 status = %q, want %q (detail: %s)", probe8.Status, tc.wantStatus, probe8.Detail)
			}
			if tc.wantDetail != "" && !strings.Contains(probe8.Detail, tc.wantDetail) {
				t.Fatalf("probe 8 detail = %q, want it to contain %q", probe8.Detail, tc.wantDetail)
			}
		})
	}
}

// TestRunContainmentConformance_ChainTextWithoutOutputHookIsUnknown covers
// conformanceChainDropCounter's "not the managed output base chain" branch:
// chain text that parses but declares a chain not attached to the output
// hook (e.g. missing the `type filter hook output ...` decl) must not be
// treated as attributable, matching production's own guard against a
// lookalike chain the direct-canary packet never traverses.
func TestRunContainmentConformance_ChainTextWithoutOutputHookIsUnknown(t *testing.T) {
	chainText := "table inet " + defaultNFTTable + " {\n" +
		"\tchain " + defaultNFTChain + " {\n" +
		"\t\tmeta skuid 988 accept\n" +
		"\t\tmeta skuid 987 counter packets 9 bytes 900 drop\n" +
		"\t}\n" +
		"}\n"
	env := ConformanceEnv{
		RunCommand:   conformanceRunner(cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7}, cannedResp{out: "200", code: 0}),
		NFTChainText: chainText,
		AgentUID:     987,
		ProxyUID:     988,
	}
	results, _, err := RunContainmentConformance(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range results {
		if r.Probe == 8 {
			if r.Status == ConformanceStatusPass {
				t.Fatalf("chain text without the output hook must never resolve to PASS; got status %q detail %q", r.Status, r.Detail)
			}
			if !strings.Contains(r.Detail, "not the managed output base chain") {
				t.Fatalf("probe 8 detail = %q, want it to mention the missing output base chain", r.Detail)
			}
		}
	}
}

// TestRunContainmentConformance_MalformedChainTextFailsClosed proves that
// chain text the recognizer cannot parse never resolves to PASS: it must
// surface as UNKNOWN (inconclusive attribution), the same fail-closed
// direction production's readContainmentDropCounter takes on a parse error.
func TestRunContainmentConformance_MalformedChainTextFailsClosed(t *testing.T) {
	env := ConformanceEnv{
		RunCommand:   conformanceRunner(cannedResp{out: "curl: (7) refused\nPLK_TIME_CONNECT=0.000000\n000", code: 7}, cannedResp{out: "200", code: 0}),
		NFTChainText: "this is not valid nft chain output",
		AgentUID:     987,
		ProxyUID:     988,
	}
	results, _, err := RunContainmentConformance(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range results {
		if r.Probe == 8 && r.Status == ConformanceStatusPass {
			t.Fatalf("malformed chain text must never resolve to PASS; got status %q detail %q", r.Status, r.Detail)
		}
	}
}
