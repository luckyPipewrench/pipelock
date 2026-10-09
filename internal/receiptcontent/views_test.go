// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// canaryFixture is a configured canary, split into fragments below the
// partial-secret threshold by the reconstruction tests.
const canaryFixture = "r3Aa1Bb2Cc3Dd4Ee5Ff6"

const (
	anchoredRule   = "anchored-fixture"
	structuredRule = "structured-fixture"
)

// githubFixture builds a synthetic GitHub token at runtime so the source never
// carries a credential-shaped literal.
func githubFixture() string { return "gh" + "p_" + strings.Repeat("a1B2", 9) }

func testDetector(t *testing.T) Detector {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: anchoredRule, Regex: `^anchorfixture[0-9]{6}$`, Severity: config.SeverityHigh},
		config.DLPPattern{Name: structuredRule, Regex: `"actor":"rightfixture","principal":"leftfixture"`, Severity: config.SeverityHigh},
	)
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "boundary_canary", Value: canaryFixture}}}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatalf("scanner.New: %v", err)
	}
	t.Cleanup(sc.Close)
	return sc.ScanTextForDLPQuiet
}

var testProducer = Register(Schema{
	Kind: "test.kind",
	Fields: map[string]Class{
		"version":    Generated,
		"signature":  Generated,
		"crypto":     Generated,
		"id":         ProvenID,
		"parent":     Identity,
		"verdict":    Enum,
		"note":       Content,
		"list":       Content,
		"list[]":     Content,
		"nested":     Content,
		"nested.gen": Generated,
		"ext":        Dynamic,
		"ext.*":      Content,
	},
	Enums: map[string][]string{"verdict": {"allow", "block"}},
	Outer: func(detail []byte) (Outer, error) {
		var d struct {
			Verdict string `json:"verdict"`
		}
		if err := json.Unmarshal(detail, &d); err != nil {
			return Outer{}, err
		}
		return Outer{Type: "test", Summary: "test: " + d.Verdict}, nil
	},
})

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func scanDetail(t *testing.T, det Detector, detail []byte) (Report, error) {
	t.Helper()
	p, err := ProjectUnproven(detail, nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	return Scan(context.Background(), det, p)
}

func requireView(t *testing.T, rep Report, err error, view View) {
	t.Helper()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if rep.Clean() {
		t.Fatalf("scan clean; want %s finding", view)
	}
	if got := rep.Findings[0].View; got != view {
		t.Fatalf("finding view = %s, want %s (%+v)", got, view, rep.Findings)
	}
	rej := rep.Err()
	if !errors.Is(rej, ErrRejected) {
		t.Fatalf("Err() = %v, want ErrRejected", rej)
	}
}

// requireClean asserts det(text) is clean: a precondition proving that the
// views not under test cannot catch the counterexample.
func requireClean(t *testing.T, det Detector, label, text string) {
	t.Helper()
	if res := det(context.Background(), text); !res.Clean {
		t.Fatalf("precondition: %s is not clean (%s)", label, firstPattern(res))
	}
}

func TestScanAtomViewOnlyCatchesAnchoredRule(t *testing.T) {
	det := testDetector(t)
	detail := mustJSON(t, map[string]any{"a": "unrelated", "b": "anchorfixture123456", "c": "other"})
	p, err := ProjectUnproven(detail, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireClean(t, det, "structured view", string(p.Structured()))
	requireClean(t, det, "values join", "unrelatedanchorfixture123456other")
	rep, err := Scan(context.Background(), det, p)
	requireView(t, rep, err, ViewAtom)
	if rep.Findings[0].Paths[0] != "b" || rep.Findings[0].Pattern != anchoredRule {
		t.Fatalf("finding = %+v", rep.Findings[0])
	}
}

func TestScanAtomViewCatchesCanaryInKeyAndEscapedValue(t *testing.T) {
	det := testDetector(t)
	escaped := `{"x":"` + strings.ReplaceAll(canaryFixture, "r3", `r3`) + `"}`
	rep, err := scanDetail(t, det, []byte(escaped))
	requireView(t, rep, err, ViewAtom)

	rep, err = scanDetail(t, det, mustJSON(t, map[string]any{canaryFixture: "v"}))
	requireView(t, rep, err, ViewAtom)
	if !rep.Findings[0].Key || rep.Redactable() {
		t.Fatalf("member-name hit must be a non-redactable key finding: %+v", rep.Findings[0])
	}
	if msg := rep.Err().Error(); strings.Contains(msg, canaryFixture) || !strings.Contains(msg, `"*"`) {
		t.Fatalf("rejection must report the schema path, never the member name: %s", msg)
	}
}

func TestScanValuesJoinOnlyCatchesManyAdjacentParts(t *testing.T) {
	det := testDetector(t)
	var parts []string
	for i := 0; i < len(canaryFixture); i += 3 {
		parts = append(parts, canaryFixture[i:min(i+3, len(canaryFixture))])
	}
	// One array keeps seven 3-byte fragments adjacent in value order. Any four
	// of them stay below the 16-byte partial-canary threshold, so the bounded
	// fragment view cannot see the token and only the values join can.
	detail := mustJSON(t, map[string]any{"list": parts})
	p, err := ProjectUnproven(detail, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireClean(t, det, "structured view", string(p.Structured()))
	for _, part := range parts {
		requireClean(t, det, "fragment", part)
	}
	f, err := scanFragments(context.Background(), det, p)
	if err != nil || f != nil {
		t.Fatalf("precondition: fragment view = %+v, %v; want clean", f, err)
	}
	rep, err := Scan(context.Background(), det, p)
	requireView(t, rep, err, ViewValues)
}

func TestScanInterleavedKeysValuesJoinReassembles(t *testing.T) {
	// Round-3 F1: [left, first-half, right, second-half] passed a full join
	// that included member names. The values-only view must reassemble it.
	det := testDetector(t)
	detail := mustJSON(t, map[string]any{"ext": map[string]any{"left": canaryFixture[:10], "right": canaryFixture[10:]}})
	requireClean(t, det, "full join with keys", "left"+canaryFixture[:10]+"right"+canaryFixture[10:])
	rep, err := scanDetail(t, det, detail)
	requireView(t, rep, err, ViewValues)
}

func TestScanFragmentsOnlyCatchesNonAdjacentSplits(t *testing.T) {
	det := testDetector(t)
	tok := githubFixture()
	cases := []struct {
		name   string
		values []string
	}{
		{"two-part canary around an unrelated value", []string{canaryFixture[:10], "x.y", canaryFixture[10:]}},
		{"three-part canary across extension and core fields", []string{"core.v", canaryFixture[:7], "x.y", canaryFixture[7:14], "z.w", canaryFixture[14:]}},
	}
	t.Run("three-part built-in token between unrelated values is rejected", func(t *testing.T) {
		// Round-3 counterexample. The scanner's noise-stripped view already
		// reassembles a built-in token across punctuation, so any view may
		// catch it; the requirement is rejection.
		fields := map[string]any{"f0": tok[:13], "f1": "!", "f2": tok[13:26], "f3": "!", "f4": tok[26:]}
		for _, part := range []string{tok[:13], tok[13:26], tok[26:]} {
			requireClean(t, det, "fragment", part)
		}
		rep, err := scanDetail(t, det, mustJSON(t, fields))
		if err != nil || rep.Clean() {
			t.Fatalf("split built-in token accepted: %+v %v", rep, err)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]any{}
			for i, v := range tc.values {
				fields["f"+strconv.Itoa(i)] = v
			}
			p, err := ProjectUnproven(mustJSON(t, fields), nil)
			if err != nil {
				t.Fatal(err)
			}
			requireClean(t, det, "structured view", string(p.Structured()))
			requireClean(t, det, "values join", strings.Join(tc.values, ""))
			rep, err := Scan(context.Background(), det, p)
			requireView(t, rep, err, ViewFragments)
			if len(rep.Findings[0].Paths) < 2 {
				t.Fatalf("fragment finding must name every participating path: %+v", rep.Findings[0])
			}
		})
	}
}

func TestScanStructuredOnlyCatchesContextRule(t *testing.T) {
	// Round-3 F3: a supported rule over field context matches only the
	// structured projection; parts and their joins are clean.
	det := testDetector(t)
	detail := mustJSON(t, map[string]any{"actor": "rightfixture", "principal": "leftfixture"})
	for _, text := range []string{"actor", "rightfixture", "principal", "leftfixture", "rightfixtureleftfixture", "actorrightfixtureprincipalleftfixture"} {
		requireClean(t, det, "part "+text, text)
	}
	rep, err := scanDetail(t, det, detail)
	requireView(t, rep, err, ViewStructured)
}

func TestScanCleanProjection(t *testing.T) {
	det := testDetector(t)
	rep, err := scanDetail(t, det, mustJSON(t, map[string]any{"target": "https://api.vendor.example/v1/items", "method": "GET", "n": 3}))
	if err != nil || !rep.Clean() || rep.Err() != nil || rep.Redactable() {
		t.Fatalf("clean receipt rejected: %+v %v", rep, err)
	}
}

func TestScanBudgetExhaustionRejects(t *testing.T) {
	det := testDetector(t)
	t.Run("too many distinct atoms", func(t *testing.T) {
		fields := map[string]any{}
		for i := 0; i <= scanner.SubsequenceMaxParts; i++ {
			fields["k"] = nil
			fields["f"+strconv.Itoa(i)] = "value" + strconv.Itoa(i)
		}
		delete(fields, "k")
		p, err := testProducer.Project(mustJSON(t, map[string]any{"verdict": "allow", "nested": fields}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Scan(context.Background(), det, p)
		var rej *RejectionError
		if !errors.As(err, &rej) || rej.View != ViewBudget || !errors.Is(err, ErrRejected) {
			t.Fatalf("err = %v, want budget rejection", err)
		}
	})
	t.Run("too much reconstruction work", func(t *testing.T) {
		// The unproven root's "list" member name is one candidate, so 19
		// values keep the candidate count at the part bound and leave only
		// the work bound to refuse.
		values := make([]string, scanner.SubsequenceMaxParts-1)
		for i := range values {
			values[i] = strings.Repeat("word"+strconv.Itoa(i)+" ", 4000)
		}
		_, err := scanDetail(t, det, mustJSON(t, map[string]any{"list": values}))
		var rej *RejectionError
		if !errors.As(err, &rej) || rej.View != ViewBudget {
			t.Fatalf("err = %v, want budget rejection", err)
		}
	})
}

func TestScanRequiresDetector(t *testing.T) {
	p, err := ProjectUnproven([]byte(`{"a":"b"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), nil, p); err == nil {
		t.Fatal("nil detector must not pass")
	}
}

func TestReportRedactableAndErrors(t *testing.T) {
	cases := []struct {
		f    Finding
		want bool
	}{
		{Finding{View: ViewAtom, Paths: []string{"a"}}, true},
		{Finding{View: ViewAtom, Identity: true}, false},
		{Finding{View: ViewAtom, Key: true}, false},
		{Finding{View: ViewValues}, false},
	}
	for _, tc := range cases {
		if got := (Report{Findings: []Finding{tc.f}}).Redactable(); got != tc.want {
			t.Fatalf("Redactable(%+v) = %v", tc.f, got)
		}
	}
	err := (&RejectionError{Kind: "k", View: ViewAtom, Path: "p", Pattern: "pat", Identity: true, Reason: "why"}).Error()
	for _, want := range []string{"kind k", "atom view", `field "p"`, "identity field", "matched pat", "why"} {
		if !strings.Contains(err, want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestScanUnnamedDetectorHitAndEmptyLeaf(t *testing.T) {
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: !strings.Contains(text, "bad")}
	}
	rep, err := scanDetail(t, det, []byte(`{"empty":"","v":"bad"}`))
	requireView(t, rep, err, ViewAtom)
	if rep.Findings[0].Pattern != "detector" || len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
}

func TestBinomialAndWork(t *testing.T) {
	if binomial(5, 2) != 10 || binomial(3, 4) != 0 || binomial(3, -1) != 0 {
		t.Fatal("binomial")
	}
	if got := fragmentWorkBytes([]string{"ab", "c"}); got != 3 {
		t.Fatalf("work = %d, want 3", got)
	}
}
