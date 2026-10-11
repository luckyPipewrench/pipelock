// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// outcomeDetail is a v1 outcome receipt shaped like the forward-proxy
// receipts a load run writes, without the fields the producer generates.
func outcomeDetail(t *testing.T, n int, actor, pattern string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"version": 1,
		"action_record": map[string]any{
			"version": 1, "action_type": "read", "principal": "local", "actor": actor,
			"target":            fmt.Sprintf("https://api.vendor.example/ok?wk=s1-r7c4fa80948a5bdd333d89a1148e4999e-m%06d", n),
			"side_effect_class": "external_read", "reversibility": "full", "verdict": "allow",
			"decision_phase": "outcome", "session_taint_level": "trusted", "authority_kind": "user_broad",
			"taint_decision": "allow", "taint_decision_reason": "taint_safe_read_only_action",
			"transport": "forward", "method": "GET", "layer": "outcome", "pattern": pattern,
			"request_id": fmt.Sprintf("req-%d", n),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestCachedReceiptDetectorMatchesScalar runs the production detector with and
// without the clean cache over a sequence of real-shaped receipts, including
// secrets that only the fragment and bridge searches reassemble. Every report
// must be identical, on a cold cache and again on a warm one.
func TestCachedReceiptDetectorMatchesScalar(t *testing.T) {
	// A secret the process holds, containing the principal "local" that the
	// emitter marks as a fixed bridge, split by the caller around it.
	bridgeLeft, bridgeRight := "Zq8xV2", "M9pR4tK7wY1nB3"
	t.Setenv("PIPELOCK_TEST_RECEIPT_BRIDGE_SECRET", bridgeLeft+"local"+bridgeRight)
	token := "ghp_" + strings.Repeat("aB3dE5", 6) // 36 characters after the prefix
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	producer := actionReceiptProducer.WithFixedValues(map[string][]string{
		"action_record.principal": {"local"},
		"action_record.actor":     {"pipelock"},
	})
	const clean = "status=200 bytes=2 reason=complete"
	cases := []struct {
		name      string
		detail    []byte
		wantClean bool
		view      receiptcontent.View
	}{
		{"clean first request", outcomeDetail(t, 1, "anonymous", clean), true, ""},
		{"clean second request", outcomeDetail(t, 2, "anonymous", clean), true, ""},
		// The alphanumeric layer label between the halves extends the token
		// run, so the joined values already hold it.
		{"token split across caller fields", outcomeDetail(t, 3, token[:20], token[20:]), false, receiptcontent.ViewValues},
		{"token split in reverse field order", outcomeDetail(t, 4, token[20:], token[:20]), false, receiptcontent.ViewFragments},
		{"secret completed only by the fixed principal", outcomeDetail(t, 5, bridgeLeft, bridgeRight), false, receiptcontent.ViewFragments},
		{"bridged secret in reverse field order", outcomeDetail(t, 6, bridgeRight, bridgeLeft), false, receiptcontent.ViewFragments},
		{"clean after dirty", outcomeDetail(t, 7, "anonymous", clean), true, ""},
		{"configured actor", outcomeDetail(t, 8, "pipelock", clean), true, ""},
	}

	scalar := receiptcontent.Detector(sc.ScanTextForDLPQuiet)
	cached, err := receiptcontent.NewCachedDetector(scalar, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for pass := range 2 {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("pass%d/%s", pass, tc.name), func(t *testing.T) {
				p, err := producer.Project(tc.detail)
				if err != nil {
					t.Fatal(err)
				}
				want, wantErr := receiptcontent.Scan(ctx, scalar, p)
				got, gotErr := receiptcontent.Scan(ctx, cached.Detect, p)
				if fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
					t.Fatalf("error: scalar %v, cached %v", wantErr, gotErr)
				}
				if !reflect.DeepEqual(want.Findings, got.Findings) {
					t.Fatalf("findings differ:\nscalar %+v\ncached %+v", want.Findings, got.Findings)
				}
				if want.Clean() != tc.wantClean {
					t.Fatalf("scalar clean = %v, want %v (findings %+v)", want.Clean(), tc.wantClean, want.Findings)
				}
				if !tc.wantClean && want.Findings[0].View != tc.view {
					t.Fatalf("attack found in %s view, want %s", want.Findings[0].View, tc.view)
				}
			})
		}
	}
	if cached.Len() == 0 {
		t.Fatal("clean receipts left nothing in the cache")
	}
}
