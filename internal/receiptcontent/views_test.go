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
	t.Run("width alone is not a refusal", func(t *testing.T) {
		// One past the request-path part cap. The producer's outer mirror adds
		// two more atoms. The work of a full size-2..4 search of these short
		// parts is under the byte budget; the receipt used to be refused for
		// the part count alone.
		var values []string
		for i := 0; i <= scanner.SubsequenceMaxParts; i++ {
			values = append(values, strconv.Itoa(i))
		}
		p, err := testProducer.Project(mustJSON(t, map[string]any{"list": values}))
		if err != nil {
			t.Fatal(err)
		}
		parts := atomTexts(p)
		if len(parts) <= scanner.SubsequenceMaxParts {
			t.Fatalf("fixture has %d atoms, want more than %d", len(parts), scanner.SubsequenceMaxParts)
		}
		if fragmentWorkBytes(parts) > maxFragmentWorkBytes {
			t.Fatal("width fixture also exceeds the work limit")
		}
		calls := 0
		counting := func(ctx context.Context, text string) scanner.TextDLPResult {
			calls++
			return det(ctx, text)
		}
		rep, err := Scan(context.Background(), counting, p)
		if err != nil || !rep.Clean() {
			t.Fatalf("wide clean receipt refused: %+v %v", rep, err)
		}
		// Size 4 on this width schedules more detector calls than the 20-part
		// search. The wide path stops at size 3.
		full, ok := combinationCandidates(len(parts), scanner.SubsequenceMaxSize)
		if !ok {
			t.Fatal("candidate count overflow")
		}
		limit, ok := combinationCandidates(scanner.SubsequenceMaxParts, scanner.SubsequenceMaxSize)
		if !ok || calls > int(limit)+len(parts)+2 || int64(calls) >= full {
			t.Fatalf("detector called %d times; full size-4 search is %d calls, 20-part ceiling %d", calls, full, limit)
		}
	})
	t.Run("too much reconstruction work", func(t *testing.T) {
		// The unproven root's "list" member name is one candidate, so 19
		// values keep the candidate count at the part bound and leave only
		// the work bound to refuse. The values repeat, so the work comes from
		// multiplicity: every occurrence is a separate candidate.
		values := make([]string, scanner.SubsequenceMaxParts-1)
		for i := range values {
			values[i] = strings.Repeat("abc.", 25)
		}
		p, err := ProjectUnproven(mustJSON(t, map[string]any{"list": values}), nil)
		if err != nil {
			t.Fatal(err)
		}
		parts := make([]string, 0, len(p.atoms))
		distinct := map[string]struct{}{}
		for _, a := range p.atoms {
			parts = append(parts, a.Text)
			distinct[a.Text] = struct{}{}
		}
		if len(parts) > scanner.SubsequenceMaxParts || fragmentWorkBytes(parts) <= maxFragmentWorkBytes {
			t.Fatalf("fixture must exceed only the work bound: %d parts, %d work bytes", len(parts), fragmentWorkBytes(parts))
		}
		// The bound refuses before any combination is built: the detector
		// sees each distinct atom, the structured view and the values join,
		// and no fragment candidate.
		calls := 0
		counting := func(ctx context.Context, text string) scanner.TextDLPResult {
			calls++
			return det(ctx, text)
		}
		_, err = Scan(context.Background(), counting, p)
		var rej *RejectionError
		if !errors.As(err, &rej) || rej.View != ViewBudget {
			t.Fatalf("err = %v, want budget rejection", err)
		}
		if limit := len(distinct) + 2; calls > limit {
			t.Fatalf("detector called %d times, want at most %d: reconstruction ran before the work bound", calls, limit)
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
	if got := fragmentWorkBytes([]string{"ab", "c"}); got != 6 { // one pair, both orders
		t.Fatalf("work = %d, want 6", got)
	}
	// C(20,2)*2 + C(20,3)*6 + C(20,4)*2. The wide path may not schedule more
	// detector calls than this search.
	got, ok := combinationCandidates(scanner.SubsequenceMaxParts, scanner.SubsequenceMaxSize)
	if !ok || got != 16910 {
		t.Fatalf("20-part candidate count = %d ok=%v, want 16910", got, ok)
	}
	wide, ok := combinationCandidates(30, 3)
	if !ok || wide <= got {
		t.Fatalf("30-part size-3 count = %d, want above the 20-part ceiling", wide)
	}
}

// TestWideFragmentSearchKeepsCompleteSmallerSizes pins the search that runs
// once a receipt is past the 20-part cap. A two-part and a three-part split
// are caught while size 3 still fits. Past the candidate ceiling, pairs are
// still caught and a three-part split is outside the bound. A wide receipt
// whose pairs do not fit the byte budget is refused before any fragment
// candidate is built.
func TestWideFragmentSearchKeepsCompleteSmallerSizes(t *testing.T) {
	det := testDetector(t)
	canary := canaryFixture

	t.Run("two-part split past the part cap", func(t *testing.T) {
		values := wideFillers(scanner.SubsequenceMaxParts, canary[:11], canary[11:])
		rep, err := scanList(t, det, values)
		requireView(t, rep, err, ViewFragments)
	})
	t.Run("three-part split while size 3 fits", func(t *testing.T) {
		// ProjectUnproven adds the member name, so 21 values is 22 atoms:
		// past the part cap, and still inside the size-3 candidate ceiling.
		values := wideFillers(scanner.SubsequenceMaxParts+1, canary[:7], canary[7:14], canary[14:])
		rep, err := scanList(t, det, values)
		requireView(t, rep, err, ViewFragments)
	})
	t.Run("three-part split past the candidate ceiling is outside the bound", func(t *testing.T) {
		const n = 30
		values := wideFillers(n-1, canary[:7], canary[7:14], canary[14:])
		p := projectList(t, values)
		parts := atomTexts(p)
		if len(parts) != n {
			t.Fatalf("atoms = %d, want %d", len(parts), n)
		}
		size, ok := widestFragmentSearch(parts)
		if !ok || size != 2 {
			t.Fatalf("widest search = %d ok=%v, want pairs only", size, ok)
		}
		requireClean(t, det, "values join", strings.Join(values, ""))
		calls := 0
		counting := func(ctx context.Context, text string) scanner.TextDLPResult {
			calls++
			return det(ctx, text)
		}
		rep, err := Scan(context.Background(), counting, p)
		if err != nil || !rep.Clean() {
			t.Fatalf("three-part split on a pair-only receipt: report %+v, err %v", rep.Findings, err)
		}
		if calls > 2000 {
			t.Fatalf("detector called %d times; size 3 ran on a pair-only receipt", calls)
		}
	})
	t.Run("pairs that do not fit are refused before reconstruction", func(t *testing.T) {
		const n = 50
		values := make([]string, n-1)
		for i := range values {
			values[i] = strings.Repeat("abc.", 2048)
		}
		p := projectList(t, values)
		parts := atomTexts(p)
		if _, ok := widestFragmentSearch(parts); ok {
			t.Fatal("fixture fits a wide search; it must exceed the pair budget")
		}
		distinct := map[string]struct{}{}
		for _, part := range parts {
			distinct[part] = struct{}{}
		}
		calls := 0
		counting := func(ctx context.Context, text string) scanner.TextDLPResult {
			calls++
			return det(ctx, text)
		}
		_, err := Scan(context.Background(), counting, p)
		var rej *RejectionError
		if !errors.As(err, &rej) || rej.View != ViewBudget {
			t.Fatalf("err = %v, want budget rejection", err)
		}
		if limit := len(distinct) + 2; calls > limit {
			t.Fatalf("detector called %d times, want at most %d: reconstruction ran before the work bound", calls, limit)
		}
	})
}

func atomTexts(p *Projection) []string {
	parts := make([]string, 0, len(p.atoms))
	for _, a := range p.atoms {
		parts = append(parts, a.Text)
	}
	return parts
}

func projectList(t *testing.T, values []string) *Projection {
	t.Helper()
	p, err := ProjectUnproven(mustJSON(t, map[string]any{"list": values}), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func scanList(t *testing.T, det Detector, values []string) (Report, error) {
	t.Helper()
	p := projectList(t, values)
	requireClean(t, det, "values join", strings.Join(values, ""))
	return Scan(context.Background(), det, p)
}

// wideFillers returns n values of "x" with pieces written at even indexes, so
// the pieces are not adjacent and the values join cannot reassemble them.
func wideFillers(n int, pieces ...string) []string {
	values := make([]string, n)
	for i := range values {
		values[i] = "x"
	}
	for i, piece := range pieces {
		values[i*2] = piece
	}
	return values
}

func TestRepeatedFragmentsRetainMultiplicity(t *testing.T) {
	fragment := "rpAa1B"
	token := fragment + "2cD3eF" + fragment
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "repeated", Value: token}}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p := &Producer{schema: &Schema{Kind: "test.repeated", Fields: map[string]Class{"parts": Content, "parts[]": Content}}}
	proj, err := p.Project(mustJSON(t, map[string]any{"parts": []string{fragment, "!", "2cD3eF", "#", fragment}}))
	if err != nil {
		t.Fatal(err)
	}
	if sc.ScanTextForDLPQuiet(t.Context(), token).Clean || !sc.ScanTextForDLPQuiet(t.Context(), fragment+"!2cD3eF#"+fragment).Clean {
		t.Fatal("controls must detect the selected token and accept the polluted full join")
	}
	rep, err := Scan(t.Context(), sc.ScanTextForDLPQuiet, proj)
	requireView(t, rep, err, ViewFragments)
}
