// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestFixedValuesOnlyNarrowFragments(t *testing.T) {
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
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "operatorleft"}
	}
	rep, err := Scan(t.Context(), det, p)
	if err != nil || !rep.Clean() {
		t.Fatalf("fixed/client permutation remains searched: %+v %v", rep, err)
	}
	rep, err = Scan(t.Context(), det, original)
	requireView(t, rep, err, ViewFragments) // positive control for dropped shape
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

func TestDerivedOuterIsScannedWithoutFragmentDuplication(t *testing.T) {
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
	rep, err := Scan(t.Context(), det, p)
	if err != nil || !rep.Clean() {
		t.Fatalf("derived mirror remains a fragment candidate: %+v %v", rep, err)
	}
	rep, err = Scan(t.Context(), det, unproven)
	requireView(t, rep, err, ViewFragments)
}

func TestFixedValuesDoNotSpendClientWorkBudget(t *testing.T) {
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
	if err != nil || !rep.Clean() || calls != 24 {
		t.Fatalf("2 client atoms among 20: calls %d, report %+v, err %v", calls, rep, err)
	}
}
