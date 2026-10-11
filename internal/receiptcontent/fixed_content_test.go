// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestFixedValuesBridgeButNeverCombine(t *testing.T) {
	base := &Producer{schema: &Schema{Kind: "test.fixed", Fields: map[string]Class{"a": Content, "b": Content, "c": Content}}}
	values := map[string][]string{"b": {"operator"}}
	fixed := base.WithFixedValues(values)
	values["b"][0] = "changed"
	raw := []byte(`{"a":"left","b":"operator","c":"right"}`)
	p, err := fixed.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	original, err := base.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() == original.Digest() {
		t.Fatal("fragment eligibility must be bound by the digest")
	}
	if !p.Atoms()[1].Fixed || original.Atoms()[1].Fixed {
		t.Fatal("fixed values must be immutable and scoped to the derived producer")
	}

	for _, tc := range []struct {
		name string
		text string
		view View
	}{
		{"fixed atom still scanned", "operator", ViewAtom},
		{"all values still joined", "leftoperatorright", ViewValues},
		{"structured content preserved", string(p.Structured()), ViewStructured},
		{"client fields still reassembled in reverse", "rightleft", ViewFragments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			det := func(_ context.Context, text string) scanner.TextDLPResult {
				return scanner.TextDLPResult{Clean: text != tc.text}
			}
			rep, err := Scan(t.Context(), det, p)
			requireView(t, rep, err, tc.view)
		})
	}
	// A fixed value is one bridge piece between client fragments, in any order.
	for _, tc := range []struct{ name, text string }{
		{"fixed then client", "operatorleft"},
		{"client then fixed", "leftoperator"},
		{"fixed between clients, reversed", "rightoperatorleft"},
		{"fixed after clients", "rightleftoperator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			det := func(_ context.Context, text string) scanner.TextDLPResult {
				return scanner.TextDLPResult{Clean: text != tc.text}
			}
			rep, err := Scan(t.Context(), det, p)
			requireView(t, rep, err, ViewFragments)
			if rep.Findings[0].Paths[0] == "" || len(rep.Findings[0].Paths) < 2 {
				t.Fatalf("finding must name every participating path: %+v", rep.Findings[0])
			}
		})
	}
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "operatorleft"}
	}
	rep, err := Scan(t.Context(), det, original)
	requireView(t, rep, err, ViewFragments) // the same shape without fixed values
	changed, err := fixed.Project([]byte(`{"a":"left","b":"caller","c":"right"}`))
	if err != nil {
		t.Fatal(err)
	}
	if changed.Atoms()[1].Fixed {
		t.Fatal("a changed value must remain a client candidate")
	}
	det = func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "callerleft"}
	}
	rep, err = Scan(t.Context(), det, changed)
	requireView(t, rep, err, ViewFragments)
}

func TestFixedValuesRefuseUndeclaredOrGeneratedPaths(t *testing.T) {
	base := &Producer{schema: &Schema{Kind: "test.fixed_invalid", Fields: map[string]Class{"gen": Generated, "id": Identity, "run": RunSession}}}
	for _, field := range []string{"absent", "gen"} {
		t.Run(field, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid fixed path accepted")
				}
			}()
			base.WithFixedValues(map[string][]string{field: {"fixed"}})
		})
	}
	fixed := base.WithFixedValues(map[string][]string{"id": {"fixed"}, "run": {"fixed"}})
	next := fixed.WithFixedValues(map[string][]string{"id": {"another"}})
	p, err := next.Project([]byte(`{"id":"fixed","run":"fixed"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range p.Atoms() {
		if !a.Fixed || !a.Identity {
			t.Fatal("fixed identity lost its identity treatment")
		}
	}
}

func TestDerivedOuterBridgesButDuplicatesNothing(t *testing.T) {
	base := &Producer{schema: &Schema{Kind: "test.fixed_outer", Fields: map[string]Class{"note": Content}, Outer: func([]byte) (Outer, error) { return Outer{Type: "test", Summary: "left"}, nil }}}
	p, err := base.Project([]byte(`{"note":"right"}`))
	if err != nil {
		t.Fatal(err)
	}
	unproven, err := ProjectUnproven([]byte(`{"note":"right"}`), &Outer{Type: "test", Summary: "left"})
	if err != nil {
		t.Fatal(err)
	}
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "leftright"}
	}
	for name, proj := range map[string]*Projection{"derived mirror bridges": p, "unattested mirror is a candidate": unproven} {
		t.Run(name, func(t *testing.T) {
			rep, err := Scan(t.Context(), det, proj)
			requireView(t, rep, err, ViewFragments)
		})
	}
	// A mirror is never a client piece: with only the mirror and one client
	// atom the search is one bridge, and two mirror pieces never combine.
	twin := &Producer{schema: &Schema{Kind: "test.fixed_outer_twin", Fields: map[string]Class{"note": Content}, Outer: func([]byte) (Outer, error) {
		return Outer{Type: "left", EventKind: "mid", Summary: "right"}, nil
	}}}
	tp, err := twin.Project([]byte(`{"note":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	pair := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "leftright" && text != "rightleft"}
	}
	rep, err := Scan(t.Context(), pair, tp)
	if err != nil || !rep.Clean() {
		t.Fatalf("two mirror pieces must not combine without a client piece: %+v %v", rep, err)
	}
}

func TestFixedValuesSpendOnlyBridgedWork(t *testing.T) {
	values := make([]string, 20)
	for i := range values {
		values[i] = strings.Repeat("x", 100) + string(rune('a'+i))
	}
	base := &Producer{schema: &Schema{Kind: "test.fixed_budget", Fields: map[string]Class{"parts": Content, "parts[]": Content}}}
	raw := mustJSON(t, map[string]any{"parts": values})
	det := func(_ context.Context, _ string) scanner.TextDLPResult { return scanner.TextDLPResult{Clean: true} }
	p, err := base.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(t.Context(), det, p); err == nil {
		t.Fatal("client work overrun must refuse the receipt")
	}
	p, err = base.WithFixedValues(map[string][]string{"parts[]": values[2:]}).Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	count := func(ctx context.Context, text string) scanner.TextDLPResult { calls++; return det(ctx, text) }
	rep, err := Scan(t.Context(), count, p)
	// 20 atoms alone, the structured view and the joined values, the client
	// pair in both orders, and each of 18 fixed values as one bridge piece
	// among 2 client atoms: 2*18*2 pairs and 1*18*6 triples.
	if want := 20 + 2 + 2 + 2*18*2 + 18*6; err != nil || !rep.Clean() || calls != want {
		t.Fatalf("2 client atoms among 20: calls %d, want %d, report %+v, err %v", calls, want, rep, err)
	}
}

func TestBridgedSearchStaysInsideTheWorkBound(t *testing.T) {
	long := strings.Repeat("y", 200<<10)
	fields := map[string]Class{"f": Content, "f[]": Content}
	base := &Producer{schema: &Schema{Kind: "test.fixed_bridge_budget", Fields: fields}}
	clean := func(_ context.Context, _ string) scanner.TextDLPResult { return scanner.TextDLPResult{Clean: true} }
	t.Run("search narrows to the widest size that fits", func(t *testing.T) {
		values := []string{"a0", "a1", "a2", long}
		p, err := base.WithFixedValues(map[string][]string{"f[]": {long}}).Project(mustJSON(t, map[string]any{"f": values}))
		if err != nil {
			t.Fatal(err)
		}
		var longest int
		det := func(_ context.Context, text string) scanner.TextDLPResult {
			longest = max(longest, len(text))
			return clean(nil, text)
		}
		rep, err := Scan(t.Context(), det, p)
		if err != nil || !rep.Clean() {
			t.Fatalf("report %+v, err %v", rep, err)
		}
		if longest < len(long) {
			t.Fatalf("bridged pairs were not searched: longest text %d", longest)
		}
	})
	t.Run("pairs that cannot fit refuse the receipt", func(t *testing.T) {
		values := make([]string, 0, 21)
		for i := 0; i < 20; i++ {
			values = append(values, "c"+string(rune('a'+i)))
		}
		values = append(values, strings.Repeat("z", 400<<10))
		p, err := base.WithFixedValues(map[string][]string{"f[]": {values[20]}}).Project(mustJSON(t, map[string]any{"f": values}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Scan(t.Context(), clean, p)
		var rej *RejectionError
		if !errors.As(err, &rej) || rej.View != ViewBudget {
			t.Fatalf("err = %v, want a budget refusal", err)
		}
	})
}

func TestBridgedFourPartOrderFollowsProjectionOrder(t *testing.T) {
	// Fields sort a < b < c < d: forward is a,b,c,d and reverse d,c,b,a.
	base := &Producer{schema: &Schema{Kind: "test.fixed_bridge_order", Fields: map[string]Class{"a": Content, "b": Content, "c": Content, "d": Content}}}
	p, err := base.WithFixedValues(map[string][]string{"c": {"cc"}}).Project([]byte(`{"a":"aa","b":"bb","c":"cc","d":"dd"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"ddccbbaa"} { // forward is the joined-values view
		det := func(_ context.Context, got string) scanner.TextDLPResult {
			return scanner.TextDLPResult{Clean: got != text}
		}
		rep, err := Scan(t.Context(), det, p)
		requireView(t, rep, err, ViewFragments)
	}
	det := func(_ context.Context, got string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: got != "aaccbbdd"}
	}
	rep, err := Scan(t.Context(), det, p)
	if err != nil || !rep.Clean() {
		t.Fatalf("a 4-part order other than forward or reverse is outside the bound: %+v %v", rep, err)
	}
}

func TestEqualCandidateTextsAreScannedOnce(t *testing.T) {
	base := &Producer{schema: &Schema{Kind: "test.fixed_dedup", Fields: map[string]Class{"l": Content, "l[]": Content, "f": Content}}}
	p, err := base.WithFixedValues(map[string][]string{"f": {"fx"}}).Project([]byte(`{"l":["x","x","x"],"f":"fx"}`))
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]int{}
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		calls[text]++
		return scanner.TextDLPResult{Clean: true}
	}
	if f, err := scanFragments(t.Context(), det, p); err != nil || f != nil {
		t.Fatalf("fragments = %+v, %v", f, err)
	}
	// Three equal client atoms make 6 ordered pairs and 6 ordered triples that
	// build 2 distinct texts; each bridged combination likewise builds one.
	for text, n := range calls {
		if n != 1 {
			t.Errorf("%q scanned %d times", text, n)
		}
	}
	// Equal pieces stay distinct candidates for the combination itself: a
	// token that needs the same bytes twice is still found.
	twice := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "xx"}
	}
	f, err := scanFragments(t.Context(), twice, p)
	if err != nil || f == nil || f.View != ViewFragments {
		t.Fatalf("a token built from one value twice was lost: %+v, %v", f, err)
	}
}

func TestRepeatedFixedValueIsOneBridge(t *testing.T) {
	const copies = 200
	fixed := strings.Repeat("p", 1000)
	list := make([]string, 0, copies+20)
	for i := 0; i < 20; i++ {
		list = append(list, "c"+string(rune('a'+i)))
	}
	for i := 0; i < copies; i++ {
		list = append(list, fixed)
	}
	base := &Producer{schema: &Schema{Kind: "test.fixed_repeat", Fields: map[string]Class{"l": Content, "l[]": Content}}}
	p, err := base.WithFixedValues(map[string][]string{"l[]": {fixed}}).Project(mustJSON(t, map[string]any{"l": list}))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	det := func(_ context.Context, _ string) scanner.TextDLPResult {
		calls++
		return scanner.TextDLPResult{Clean: true}
	}
	rep, err := Scan(t.Context(), det, p)
	if err != nil || !rep.Clean() {
		t.Fatalf("200 copies of one fixed value must count once: %+v %v", rep, err)
	}
	if calls == 0 {
		t.Fatal("nothing was scanned")
	}
}
