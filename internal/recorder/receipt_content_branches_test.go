// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

var noOuterTestProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:   "recorder.test.no_outer",
	Fields: map[string]receiptcontent.Class{"note": receiptcontent.Content},
})

func TestReceiptContentErrorBranches(t *testing.T) {
	rec, _ := contentTestRecorder(t, "branchfixture")
	other, _ := contentTestRecorder(t, "branchfixture")
	off, err := New(Config{Enabled: true, Dir: t.TempDir()}, nil, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = off.Close() })
	ctx := context.Background()
	clean := []byte(`{"sig":"x","note":"ok"}`)

	if _, _, err := rec.ScanReceiptContent(ctx, nil, clean); err == nil {
		t.Fatal("nil producer accepted")
	}
	if _, _, err := rec.ScanReceiptContent(ctx, outerTestProducer, []byte(`[1]`)); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("malformed detail err = %v", err)
	}
	rep, cs, err := rec.ScanReceiptContent(ctx, outerTestProducer, []byte(`{"note":"branchfixture"}`))
	if err != nil || cs != nil || rep.Clean() {
		t.Fatalf("dirty detail: rep clean=%t scan=%v err=%v", rep.Clean(), cs, err)
	}
	_, cs, err = rec.ScanReceiptContent(ctx, outerTestProducer, clean)
	if err != nil || cs == nil {
		t.Fatalf("clean scan: %v", err)
	}
	for name, bind := range map[string]func() error{
		"nil scan":       func() error { _, err := rec.BindReceiptContent(nil, outerTestProducer, clean); return err },
		"other recorder": func() error { _, err := other.BindReceiptContent(cs, outerTestProducer, clean); return err },
		"nil producer":   func() error { _, err := rec.BindReceiptContent(cs, nil, clean); return err },
		"other kind":     func() error { _, err := rec.BindReceiptContent(cs, noOuterTestProducer, clean); return err },
		"malformed":      func() error { _, err := rec.BindReceiptContent(cs, outerTestProducer, []byte(`[`)); return err },
	} {
		if bind() == nil {
			t.Errorf("%s: bind accepted", name)
		}
	}

	// Redaction off: nothing is scanned, the scan binds no content, and a
	// producer without a mirror derivation still cannot be bound.
	_, offScan, err := off.ScanReceiptContent(ctx, noOuterTestProducer, []byte(`{"note":"branchfixture"}`))
	if err != nil || offScan == nil {
		t.Fatalf("redaction-off scan: %v", err)
	}
	if _, err := off.BindReceiptContent(offScan, noOuterTestProducer, []byte(`{"note":"x"}`)); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("missing outer derivation err = %v", err)
	}
	if err := off.checkSessionContent("branchfixture"); err != nil {
		t.Fatalf("redaction-off session check: %v", err)
	}
	if err := rec.checkSessionContent("branchfixture"); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("dirty session err = %v", err)
	}
	// A handle past the projection bound is a budget rejection, not a pass.
	if err := rec.checkSessionContent(strings.Repeat("s", receiptcontent.MaxDetailBytes)); !errors.Is(err, receiptcontent.ErrRejected) {
		t.Fatalf("oversized session err = %v", err)
	}
	if _, err := rec.BindReceiptContent(cs, outerTestProducer, []byte(`{"sig":"x","note":"changed"}`)); !errors.Is(err, ErrContentChanged) {
		t.Fatalf("changed content err = %v", err)
	}
}

func TestLifecycleOuterDerivations(t *testing.T) {
	if o, err := GroupGateOuter(nil); err != nil || o.Type != GroupGateEntryType || o.EventKind != GroupGateEntryType {
		t.Fatalf("group gate outer = %+v, %v", o, err)
	}
	if _, err := decisionRecordOuter([]byte(`[`)); err == nil {
		t.Fatal("malformed decision record derived a mirror")
	}
	o, err := decisionRecordOuter([]byte(`{"verdict":"block"}`))
	if err != nil || o.Summary != "block: unknown" {
		t.Fatalf("decision outer = %+v, %v", o, err)
	}
}
