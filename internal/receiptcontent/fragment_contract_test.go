// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestFragmentReconstructionContract pins the fragment view's bound for a
// receipt inside scanner.SubsequenceMaxParts. Joins use
// scanner.SubsequenceMaxSize or fewer parts in projection order, skipping
// unrelated parts between; the receipt view also tries every order of two or
// three parts and the reverse of four. Widening that search is a scanner-wide
// decision that has to move both paths together, so the cases outside the
// bound are recorded here as outside it, not as guarantees. A wider receipt
// degrades to a complete smaller search instead of refusing for width;
// docs/guides/receipt-verification.md states both bounds.
func TestFragmentReconstructionContract(t *testing.T) {
	const whole = "r4Aa1Bb2Cc3Dd4Ee5Ff6"
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "split-token", Regex: "^" + whole + "$", Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	if sc.ScanTextForDLPQuiet(t.Context(), whole).Clean {
		t.Fatal("positive control: the whole token must match")
	}
	p := &Producer{schema: &Schema{Kind: "test.fragment_contract", Fields: map[string]Class{"parts": Content, "parts[]": Content}}}
	scan := func(t *testing.T, parts ...string) (Report, error) {
		t.Helper()
		proj, err := p.Project(mustJSON(t, map[string]any{"parts": parts}))
		if err != nil {
			t.Fatal(err)
		}
		return Scan(t.Context(), sc.ScanTextForDLPQuiet, proj)
	}
	a, b, c, d := whole[:5], whole[5:10], whole[10:15], whole[15:]

	t.Run("four pieces in order with unrelated parts between", func(t *testing.T) {
		rep, err := scan(t, a, "!", b, "#", c, "$", d)
		requireView(t, rep, err, ViewFragments)
	})
	t.Run("four pieces reversed", func(t *testing.T) {
		rep, err := scan(t, d, "!", c, "#", b, "$", a)
		requireView(t, rep, err, ViewFragments)
	})

	// Outside the bound, as on the request path's subsequence search: four
	// pieces in an order other than forward or reverse, and five pieces.
	// Both scan without a budget refusal and are not reassembled.
	t.Run("outside: four pieces in another order", func(t *testing.T) {
		rep, err := scan(t, b, "!", a, "#", c, "$", d)
		if err != nil || !rep.Clean() {
			t.Fatalf("shuffled four-piece split: report %+v, err %v; if reassembly was widened, update the guide and the request path together", rep.Findings, err)
		}
	})
	t.Run("outside: five pieces", func(t *testing.T) {
		rep, err := scan(t, whole[:4], "!", whole[4:8], "!", whole[8:12], "!", whole[12:16], "!", whole[16:])
		if err != nil || !rep.Clean() {
			t.Fatalf("five-piece split: report %+v, err %v; if reassembly was widened, update the guide and the request path together", rep.Findings, err)
		}
	})
}
