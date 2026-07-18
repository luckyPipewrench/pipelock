// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWireLabelsRemainStableAtEnumBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  fmt.Stringer
		want string
	}{
		{name: "taint trusted", got: TaintTrusted, want: "trusted"},
		{name: "taint internal", got: TaintInternalGenerated, want: "internal_generated"},
		{name: "taint allowlisted", got: TaintAllowlistedReference, want: "allowlisted_reference"},
		{name: "taint low risk", got: TaintExternalLowRisk, want: "external_low_risk"},
		{name: "taint untrusted", got: TaintExternalUntrusted, want: "external_untrusted"},
		{name: "taint hostile", got: TaintExternalHostile, want: "external_hostile"},
		{name: "taint out of range", got: TaintLevel(255), want: taintUnknownLabel},
		{name: "action read", got: ActionClassRead, want: "read"},
		{name: "action browse", got: ActionClassBrowse, want: "browse"},
		{name: "action summarize", got: ActionClassSummarize, want: "summarize"},
		{name: "action write", got: ActionClassWrite, want: "write"},
		{name: "action exec", got: ActionClassExec, want: "exec"},
		{name: "action secret", got: ActionClassSecret, want: "secret"},
		{name: "action publish", got: ActionClassPublish, want: "publish"},
		{name: "action network", got: ActionClassNetwork, want: "network"},
		{name: "action out of range", got: ActionClass(255), want: taintUnknownLabel},
		{name: "sensitivity normal", got: SensitivityNormal, want: "normal"},
		{name: "sensitivity elevated", got: SensitivityElevated, want: "elevated"},
		{name: "sensitivity protected", got: SensitivityProtected, want: "protected"},
		{name: "sensitivity out of range", got: ActionSensitivity(255), want: taintUnknownLabel},
		{name: "authority unknown", got: AuthorityUnknown, want: taintUnknownLabel},
		{name: "authority external", got: AuthorityExternal, want: "external"},
		{name: "authority policy", got: AuthorityPolicy, want: "policy"},
		{name: "authority broad user", got: AuthorityUserBroad, want: "user_broad"},
		{name: "authority exact user", got: AuthorityUserExact, want: "user_exact"},
		{name: "authority operator", got: AuthorityOperatorOverride, want: "operator_override"},
		{name: "authority out of range", got: AuthorityKind(255), want: taintUnknownLabel},
		{name: "decision allow", got: PolicyAllow, want: "allow"},
		{name: "decision warn", got: PolicyWarn, want: "warn"},
		{name: "decision ask", got: PolicyAsk, want: "ask"},
		{name: "decision block", got: PolicyBlock, want: "block"},
		{name: "decision out of range", got: PolicyDecision(255), want: taintUnknownLabel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.got.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSessionRiskObservationRetainsStrongestStateAndNewestSources(t *testing.T) {
	t.Parallel()

	var nilRisk *SessionRisk
	nilRisk.Observe(RiskObservation{PromptHit: true})

	start := time.Now().UTC()
	approvedUntil := start.Add(10 * time.Minute)
	risk := SessionRisk{}
	for i := range defaultTaintSourceLimit + 2 {
		risk.Observe(RiskObservation{
			Source: TaintSourceRef{
				URL:   fmt.Sprintf("https://source-%02d.example/input", i),
				Kind:  "http_response",
				Level: TaintExternalLowRisk,
			},
			ApprovedUntil: approvedUntil.Add(time.Duration(i) * time.Minute),
		})
	}

	if got := len(risk.Sources); got != defaultTaintSourceLimit {
		t.Fatalf("source count = %d, want %d", got, defaultTaintSourceLimit)
	}
	if got := risk.Sources[0].URL; got != "https://source-02.example/input" {
		t.Fatalf("oldest retained source = %q, want source 02", got)
	}
	if got := risk.Sources[len(risk.Sources)-1].URL; got != "https://source-11.example/input" {
		t.Fatalf("newest retained source = %q, want source 11", got)
	}
	if risk.Sources[0].Timestamp.IsZero() {
		t.Fatal("zero observation time was not initialized")
	}
	if want := approvedUntil.Add(11 * time.Minute); !risk.ApprovedUntil.Equal(want) {
		t.Fatalf("approval expiry = %v, want %v", risk.ApprovedUntil, want)
	}

	risk.Observe(RiskObservation{
		Source: TaintSourceRef{
			URL:         "https://hostile.example/instruction",
			Kind:        "http_response",
			Level:       TaintExternalLowRisk,
			MatchReason: "specific_detector",
		},
		PromptHit: true,
	})
	if risk.Level != TaintExternalHostile || !risk.Contaminated {
		t.Fatalf("hostile observation left risk at level=%s contaminated=%v", risk.Level, risk.Contaminated)
	}
	if got := risk.Sources[len(risk.Sources)-1].MatchReason; got != "specific_detector" {
		t.Fatalf("match reason = %q, want detector-provided reason", got)
	}

	snapshot := risk.Snapshot()
	snapshot.Sources[0].URL = "https://changed.example"
	if risk.Sources[0].URL == snapshot.Sources[0].URL {
		t.Fatal("snapshot mutation changed live source history")
	}
}

func TestMalformedAndEmptySourcesStayUntrusted(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{"", "relative/path", "http://"} {
		if got := ClassifyURLSource(rawURL, []string{"trusted.example"}); got != TaintExternalUntrusted {
			t.Errorf("ClassifyURLSource(%q) = %s, want external_untrusted", rawURL, got)
		}
	}

	internal := ClassifyMCPResponseObservation("tool_result", false, false)
	if internal.Source.Level != TaintInternalGenerated {
		t.Fatalf("internal MCP output level = %s, want internal_generated", internal.Source.Level)
	}
	external := ClassifyMCPResponseObservation("tool_result", true, true)
	if external.Source.Level != TaintExternalUntrusted || !external.PromptHit {
		t.Fatalf("external MCP observation = %+v, want untrusted prompt hit", external)
	}

	class, sensitivity := ClassifyHTTPAction("POST", "/account/profile", nil, nil)
	if class != ActionClassPublish || sensitivity != SensitivityNormal {
		t.Fatalf("HTTP mutation = (%s, %s), want (publish, normal)", class, sensitivity)
	}
}

func TestMalformedToolArgumentsDoNotHideSensitiveIntent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tool      string
		args      string
		wantClass ActionClass
	}{
		{
			name:      "truncated write object",
			tool:      "mystery",
			args:      `{"path":"/tmp/result","content":"unfinished`,
			wantClass: ActionClassWrite,
		},
		{
			name:      "truncated delete request",
			tool:      "mystery",
			args:      `{"method":"delete","url":"https://api.vendor.example/item"`,
			wantClass: ActionClassPublish,
		},
		{
			name:      "command intent without known tool name",
			tool:      "mystery",
			args:      `{"command":"printf hello"}`,
			wantClass: ActionClassExec,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := ClassifyMCPToolCallWithOptions(tc.tool, tc.args, nil, nil, ClassificationOptions{FailSafe: true})
			if got.Class != tc.wantClass {
				t.Fatalf("class = %s, want %s", got.Class, tc.wantClass)
			}
		})
	}
}

func TestIntentHelpersHandleMalformedAndNestedValues(t *testing.T) {
	t.Parallel()

	if got := flattenJSONStrings(""); got != nil {
		t.Fatalf("flatten empty JSON = %#v, want nil", got)
	}
	malformed := `{"path":"/tmp/result"`
	if got := flattenJSONStrings(malformed); len(got) != 1 || got[0] != malformed {
		t.Fatalf("flatten malformed JSON = %#v, want original input", got)
	}
	if _, ok := decodeJSONValue(""); ok {
		t.Fatal("empty JSON decoded successfully")
	}
	if _, ok := decodeJSONValue("{"); ok {
		t.Fatal("malformed JSON decoded successfully")
	}

	if firstURLLikeValue([]string{"plain", "/tmp/file"}) != "" {
		t.Fatal("non-URL values produced a URL")
	}
	if matchPathPattern("", "*/secret") || matchPathPattern("/tmp/secret", "") {
		t.Fatal("empty target or pattern matched")
	}
	if !matchPathPattern("repo/config/app.yaml", "/repo/config/*.yaml") {
		t.Fatal("root-relative pattern did not match relative path")
	}
	if !matchPathPattern("/workspace/repo/.env", "*/.env") {
		t.Fatal("suffix pattern did not match nested path")
	}

	if !hasMutatingNetworkMethod(`{"method":"PATCH"`) {
		t.Fatal("malformed mutating method was not recognized")
	}
	if hasMutatingNetworkMethod(`{"method":42}`) {
		t.Fatal("non-string method was treated as mutating")
	}
	if hasMutatingNetworkMethod(`{"method":"GET"}`) {
		t.Fatal("read-only method was treated as mutating")
	}
	nested := []any{
		map[string]any{"safe": true},
		[]any{map[string]any{"method": "DELETE"}},
	}
	if !jsonWalk(nested, func(key string, value any) bool {
		method, ok := value.(string)
		return strings.EqualFold(key, "method") && ok && method == "DELETE"
	}) {
		t.Fatal("nested array value was not visited")
	}
}

func TestHostileUnknownNetworkActionFailsClosed(t *testing.T) {
	t.Parallel()

	result := (PolicyMatrix{Profile: "balanced"}).Evaluate(
		TaintExternalHostile,
		ActionClassNetwork,
		SensitivityNormal,
		AuthorityUnknown,
	)
	if result.Decision != PolicyAllow {
		t.Fatalf("normal network decision = %s, want allow", result.Decision)
	}

	protected := (PolicyMatrix{Profile: "balanced"}).Evaluate(
		TaintExternalHostile,
		ActionClassNetwork,
		SensitivityProtected,
		AuthorityUnknown,
	)
	if protected.Decision != PolicyBlock {
		t.Fatalf("protected network decision = %s, want block", protected.Decision)
	}
}

func TestNextInvocationKeyConcurrentUniqueness(t *testing.T) {
	const workers = 64

	keys := make(chan string, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys <- NextInvocationKey("parallel")
		}()
	}
	wg.Wait()
	close(keys)

	seen := make(map[uint64]struct{}, workers)
	for key := range keys {
		suffix, ok := strings.CutPrefix(key, "parallel-")
		if !ok {
			t.Fatalf("key %q is missing prefix", key)
		}
		n, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil {
			t.Fatalf("key %q has invalid sequence: %v", key, err)
		}
		if _, duplicate := seen[n]; duplicate {
			t.Fatalf("duplicate sequence %d", n)
		}
		seen[n] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("unique keys = %d, want %d", len(seen), workers)
	}
}
