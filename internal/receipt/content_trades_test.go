// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// legacyActionReceiptProducer is the v1 schema as it stood before the
// fragment-search trades: the pattern is ordinary content, and only the
// transport and session targets are fixed. It exists so each trade below can
// show the exact detection it gives up.
var legacyActionReceiptProducer = func() *receiptcontent.Producer {
	fields := actionReceiptFields()
	fields["action_record.pattern"] = receiptcontent.Content
	// Before minting, the proxy's counter IDs never verified, so every
	// request ID was scanned as an identity.
	fields["action_record.request_id"] = receiptcontent.Identity
	return receiptcontent.Register(receiptcontent.Schema{
		Kind:   "test.action_receipt.v1.legacy",
		Fields: fields,
		Enums:  actionReceiptEnums,
		FixedValues: map[string][]string{
			"action_record.transport": {"forward"},
		},
		Outer: actionReceiptOuter,
	}).WithFixedValues(map[string][]string{"action_record.principal": {"local"}, "action_record.actor": {"pipelock"}})
}()

// liveActionReceiptProducer is what a proxy's v1 emitter scans with: the
// schema plus its configured principal and actor (see NewEmitter).
func liveActionReceiptProducer() *receiptcontent.Producer {
	return actionReceiptProducer.WithFixedValues(map[string][]string{
		"action_record.principal": {"local"},
		"action_record.actor":     {"pipelock"},
	})
}

func canaryScanner(t *testing.T, values ...string) *scanner.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	for i, v := range values {
		cfg.CanaryTokens.Tokens = append(cfg.CanaryTokens.Tokens, config.CanaryToken{Name: fmt.Sprintf("trade%d", i), Value: v})
	}
	cfg.CanaryTokens.Enabled = len(values) > 0
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, v := range values {
		if sc.ScanTextForDLPQuiet(t.Context(), v).Clean {
			t.Fatalf("positive control: canary %q must match alone", v)
		}
	}
	return sc
}

func v1Detail(t *testing.T, edit func(ar map[string]any)) []byte {
	t.Helper()
	ar := map[string]any{
		"version": 1, "action_type": "read", "principal": "local", "actor": "anonymous",
		"target":            "https://api.vendor.example/ok?wk=s1-m000001",
		"side_effect_class": "external_read", "reversibility": "full", "verdict": "allow",
		"decision_phase": "outcome", "transport": "forward", "method": "GET",
		"layer": "outcome", "pattern": "status=200 bytes=2 reason=complete", "request_id": "req-1",
	}
	if edit != nil {
		edit(ar)
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "action_record": ar})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func scanWith(t *testing.T, p *receiptcontent.Producer, sc *scanner.Scanner, detail []byte) receiptcontent.Report {
	t.Helper()
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

// TestActionReceiptFragmentTrades pins each detection trade the v1 schema
// makes for speed. Every "lost" plant is caught by the legacy schema and
// missed by the live one; undoing the trade makes the live schema catch it
// and fails the test. Every "kept" plant is caught by both.
func TestActionReceiptFragmentTrades(t *testing.T) {
	minted := receiptcontent.NewRequestID()
	if minted == "" {
		t.Fatal("request ID minting failed")
	}
	const (
		patternSecret = "Pq7Wz3Kx" + "Rv9Tn2Lm5Bd8"
		idSecret      = "Hs4Jc6Yf"
		bridgeSecret  = "Gt5Nw8Qe" + "anonymous" + "Mz4Lc8Vb"
		fixedPair     = "anonymous" + "local" + "Ub3Xk7RaQ2"
		layerPair     = "outcome" + "local" + "Ej9Fp4WyN"
	)
	sc := canaryScanner(t, patternSecret, idSecret+minted, bridgeSecret, fixedPair, layerPair)
	live := liveActionReceiptProducer()
	// Projection order is actor, layer, pattern, principal, request_id,
	// target, transport; enum values are excluded. Canary tokens also match
	// any 16-byte slice, so no piece and no accidental neighbor pair in the
	// joined values reaches 16 bytes of a plant.
	for _, tc := range []struct {
		name string
		edit func(ar map[string]any)
		lost bool
	}{
		{"pattern split with a field it does not neighbor", func(ar map[string]any) {
			ar["pattern"], ar["request_id"] = patternSecret[8:], patternSecret[:8]
		}, true},
		{"secret wholly inside the pattern", func(ar map[string]any) {
			ar["pattern"] = "status=200 reason=" + patternSecret
		}, false},
		{"pattern split with its projection neighbor", func(ar map[string]any) {
			ar["layer"], ar["pattern"] = patternSecret[:8], patternSecret[8:]
		}, false},
		{"minted request ID completing a split", func(ar map[string]any) {
			ar["actor"], ar["request_id"] = idSecret, minted
		}, true},
		{"anonymous and the principal in one candidate", func(ar map[string]any) {
			ar["request_id"] = "Ub3Xk7RaQ2"
		}, true},
		{"anonymous as the one bridge", func(ar map[string]any) {
			ar["layer"], ar["request_id"] = "Mz4Lc8Vb", "Gt5Nw8Qe"
		}, false},
		{"layer name and the principal in one candidate", func(ar map[string]any) {
			ar["request_id"] = "Ej9Fp4WyN"
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail := v1Detail(t, tc.edit)
			legacy := scanWith(t, legacyActionReceiptProducer, sc, detail)
			got := scanWith(t, live, sc, detail)
			if legacy.Clean() {
				t.Fatalf("legacy schema missed the plant: the test is not exercising a trade")
			}
			if tc.lost && !got.Clean() {
				t.Fatalf("live schema still catches the traded split in %s view; the trade is not in effect", got.Findings[0].View)
			}
			if !tc.lost && got.Clean() {
				t.Fatal("live schema lost a plant the trade must keep")
			}
		})
	}
}

// TestActionReceiptUnmintedRequestIDStaysContent keeps a request ID this
// process did not mint, including a well-formed one, in the search.
func TestActionReceiptUnmintedRequestIDStaysContent(t *testing.T) {
	const left = "Kw8Rd3Tz"
	chosen := "req-01a12bcb-6bb0-7e78-8522-f69bdaf2e4c0"
	sc := canaryScanner(t, left+chosen, left+"req-999")
	for _, id := range []string{chosen, "req-999"} {
		detail := v1Detail(t, func(ar map[string]any) { ar["actor"], ar["request_id"] = left, id })
		if scanWith(t, liveActionReceiptProducer(), sc, detail).Clean() {
			t.Fatalf("unminted request ID %q dropped out of the search", id)
		}
	}
	minted := receiptcontent.NewRequestID()
	proj, err := liveActionReceiptProducer().Project(v1Detail(t, func(ar map[string]any) { ar["request_id"] = minted }))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range proj.Atoms() {
		if strings.Contains(a.Text, strings.TrimPrefix(minted, receiptcontent.RequestIDPrefix)) {
			t.Fatalf("minted request ID projected at %s", a.Field)
		}
	}
}

// TestActionReceiptOutcomeSearchCost bounds the detector calls of a live v1
// allow outcome, so a change that undoes the trades fails here before it
// fails on a load run.
func TestActionReceiptOutcomeSearchCost(t *testing.T) {
	detail := v1Detail(t, func(ar map[string]any) { ar["request_id"] = receiptcontent.NewRequestID() })
	count := func(p *receiptcontent.Producer) int {
		proj, err := p.Project(detail)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		det := func(context.Context, string) scanner.TextDLPResult {
			calls++
			return scanner.TextDLPResult{Clean: true}
		}
		if _, err := receiptcontent.Scan(context.Background(), det, proj); err != nil {
			t.Fatal(err)
		}
		return calls
	}
	legacy, live := count(legacyActionReceiptProducer), count(liveActionReceiptProducer())
	if live*5 > legacy {
		t.Fatalf("live outcome makes %d detector calls against %d before the trades; want at least 5x fewer", live, legacy)
	}
}
