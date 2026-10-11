// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// legacyEvidenceReceiptProducer is the v2 schema before the fragment-search
// trades: the rule ID is ordinary content and the emitter's configured
// principal and actor are client fragments.
var legacyEvidenceReceiptProducer = func() *receiptcontent.Producer {
	fields := evidenceReceiptFields()
	fields["payload.rule_id"] = receiptcontent.Content
	return receiptcontent.Register(receiptcontent.Schema{
		Kind:        "test.evidence_receipt.v2.legacy",
		Fields:      fields,
		FixedValues: evidenceReceiptFixedValues,
		Outer:       evidenceReceiptOuter,
	})
}()

// TestEvidenceReceiptFragmentTrades pins each detection trade the v2 schema
// and a retained stamper make for speed. A "lost" plant is caught before the
// trade and missed after it; undoing the trade fails the test. A "kept"
// plant is caught by both.
func TestEvidenceReceiptFragmentTrades(t *testing.T) {
	const (
		ruleSecret   = "Kd3Rm8Zt" + "Wp6Lq2Nv4"
		pairSecret   = "agent" + "operator" + "Hx5Tb9Q"
		bridgeSecret = "Fv7Kc2Jd" + "operator" + "Ty4Ns8Gm"
	)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.CanaryTokens.Enabled = true
	for i, v := range []string{ruleSecret, pairSecret, bridgeSecret} {
		cfg.CanaryTokens.Tokens = append(cfg.CanaryTokens.Tokens, config.CanaryToken{Name: fmt.Sprintf("v2trade%d", i), Value: v})
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	// The fixture stamps principal "operator" and actor "agent", as an
	// emitter configured with them would.
	live := (&Stamper{name: "test.retained"}).WithRetained("operator", "agent").contentProducer()
	scan := func(p *receiptcontent.Producer, detail []byte) receiptcontent.Report {
		proj, err := p.Project(detail)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := receiptcontent.Scan(context.Background(), sc.ScanTextForDLPQuiet, proj)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	// Canary tokens match any 16-byte slice, so no piece and no neighbor
	// pair in the joined values reaches 16 bytes of a plant.
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		lost   bool
	}{
		{"rule ID split with a field it does not neighbor", func(m map[string]any) {
			m["selector_id"], m["payload"].(map[string]any)["rule_id"] = ruleSecret[:8], ruleSecret[8:]
		}, true},
		{"secret wholly inside the rule ID", func(m map[string]any) {
			m["payload"].(map[string]any)["rule_id"] = "status=200 reason=" + ruleSecret
		}, false},
		{"configured principal and actor in one candidate", func(m map[string]any) {
			m["selector_id"] = "Hx5Tb9Q"
		}, true},
		{"configured principal as the one bridge", func(m map[string]any) {
			m["selector_id"], m["contract_generation"] = "Fv7Kc2Jd", "Ty4Ns8Gm"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail := v2Detail(t, tc.mutate)
			if scan(legacyEvidenceReceiptProducer, detail).Clean() {
				t.Fatal("legacy schema missed the plant: the test is not exercising a trade")
			}
			got := scan(live, detail)
			if tc.lost && !got.Clean() {
				t.Fatalf("retained schema still catches the traded split in %s view; the trade is not in effect", got.Findings[0].View)
			}
			if !tc.lost && got.Clean() {
				t.Fatal("retained schema lost a plant the trade must keep")
			}
		})
	}
}

// TestStamperWithRetainedScopesItsProducer keeps the narrowed producer on the
// derived stamper only, ignores empty values, and binds a prescan only to the
// producer that took it.
func TestStamperWithRetainedScopesItsProducer(t *testing.T) {
	base := &Stamper{name: "test.retained_scope"}
	if base.contentProducer() != evidenceReceiptProducer {
		t.Fatal("a plain stamper must use the registered producer")
	}
	derived := base.WithRetained("operator", "")
	if derived.name != base.name || base.producer != nil || derived.producer == nil {
		t.Fatal("WithRetained must derive a new stamper and leave the original unchanged")
	}
	if (*Stamper)(nil).WithRetained("operator", "agent") != nil {
		t.Fatal("a nil stamper must stay nil")
	}
	detail := v2Detail(t, nil)
	narrowed, err := derived.contentProducer().Project(detail)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := evidenceReceiptProducer.Project(detail)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed.Digest() == plain.Digest() {
		t.Fatal("a retained projection must bind its narrower search in the digest")
	}
	for _, a := range narrowed.Atoms() {
		if a.Field == "actor" && a.Fixed {
			t.Fatal("an empty retained actor fixed the actor")
		}
		if a.Field == "principal" && !a.Fixed {
			t.Fatal("the retained principal is not fixed")
		}
	}

	// A prescan taken with the retained producer binds through the same
	// stamper, and the record path uses that producer end to end.
	rec := v2Recorder(t)
	stamper := base.WithRetained("operator", "agent")
	rcpt := v2Receipt()
	pre, err := stamper.Prescan(context.Background(), rec, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	if err := stamper.RecordPrescanned(context.Background(), rec, "test-retained", rcpt, false, pre); err != nil {
		t.Fatalf("retained stamper could not record its own prescan: %v", err)
	}
}
