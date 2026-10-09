// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestOptionalResponseDecisionPolicyHash(t *testing.T) {
	for _, surface := range []string{"proxy", "reverse"} {
		for _, supplied := range []bool{false, true} {
			t.Run(surface+"/"+map[bool]string{false: "snapshot", true: "preserved"}[supplied], func(t *testing.T) {
				f := newDualEmitFixture(t, false)
				cfg := config.Defaults()
				cfg.ResponseScanning.Action = config.ActionStrip
				opts := receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionAllow, Layer: "response_decision", Transport: TransportForward, Method: http.MethodGet, Target: "https://api.vendor.example/content"}
				want := cfg.CanonicalPolicyHash()
				if supplied {
					want = strings.Repeat("b", 64)
					opts.PolicyHash = want
				}
				var err error
				if surface == "proxy" {
					err = f.p.confirmResponseDecision(cfg, opts)
				} else {
					rp := &ReverseProxyHandler{cfgPtr: &f.p.cfgPtr, logger: f.p.logger, metrics: f.p.metrics, receiptEmitterPtr: &f.p.receiptEmitterPtr, v2EmitterPtr: &f.p.v2EmitterPtr, owner: f.p}
					err = rp.confirmResponseDecision(cfg, opts)
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := f.rec.Close(); err != nil {
					t.Fatal(err)
				}
				records := extractReceiptsFromDir(t, f.dir)
				if len(records) != 1 {
					t.Fatalf("receipts=%d", len(records))
				}
				if got := records[0].ActionRecord.PolicyHash; got != want {
					t.Fatalf("policy hash=%q want snapshot %q", got, want)
				}
			})
		}
	}
}

func TestInterceptResponseConfirmationWithoutProxy(t *testing.T) {
	cfg := config.Defaults()
	cfg.FlightRecorder.RequireReceipts = true
	w := httptest.NewRecorder()
	if !interceptConfirmResponseOrBlock(&InterceptContext{Config: cfg}, w, receipt.EmitOpts{}) || w.Code != http.StatusForbidden || w.Header().Get("X-Pipelock-Block-Reason") != "receipt_emission_failed" {
		t.Fatalf("missing proxy did not fail closed: status=%d headers=%v", w.Code, w.Header())
	}
}
