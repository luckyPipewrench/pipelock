// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func contentTestRecorder(t *testing.T, bad string) (*Recorder, string) {
	t.Helper()
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: !strings.Contains(text, bad)}
	}
	dir := t.TempDir()
	rec, err := New(Config{Enabled: true, Dir: dir, Redact: true}, det, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec, dir
}

func TestDecisionRecordSchemaCoversEveryField(t *testing.T) {
	classes := decisionRecordProducer.Classification()
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for i := 0; i < typ.NumField(); i++ {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			if _, ok := classes[path]; !ok {
				t.Errorf("decision record path %q is not classified", path)
			}
			if ft := typ.Field(i).Type; ft.Kind() == reflect.Struct && ft.PkgPath() == typ.PkgPath() {
				walk(ft, path)
			}
		}
	}
	walk(reflect.TypeOf(DecisionRecord{}), "")
}

func TestRecordDecisionIsValidateOrFailNeverRedacted(t *testing.T) {
	rec, dir := contentTestRecorder(t, "decision-secret")
	ctx := RequestEvidence{Transport: "forward"}
	dirty := DecisionRecord{SessionID: "proxy", Verdict: "block", ScannerResult: ScannerEvidence{Layer: "dlp", MatchText: "decision-secret"}, RequestContext: ctx}
	err := rec.RecordDecision(dirty)
	if !errors.Is(err, receiptcontent.ErrRejected) || strings.Contains(err.Error(), "decision-secret") {
		t.Fatalf("dirty decision err = %v, want typed rejection without echo", err)
	}
	clean := DecisionRecord{SessionID: "proxy", Verdict: "block", ScannerResult: ScannerEvidence{Layer: "dlp", Pattern: "p"}, RequestContext: ctx}
	if err := rec.RecordDecision(clean); err != nil {
		t.Fatalf("clean decision after rejection: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("evidence files = %v", files)
	}
	entries, err := ReadEntries(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var decisions int
	for _, e := range entries {
		if e.Type != decisionEntryType {
			continue
		}
		decisions++
		if e.Summary != "block: dlp (p)" {
			t.Fatalf("summary = %q", e.Summary)
		}
		if m, ok := e.Detail.(map[string]any); !ok || m["redacted"] != nil {
			t.Fatalf("decision detail was redacted after signing: %#v", e.Detail)
		}
	}
	if decisions != 1 {
		t.Fatalf("decisions written = %d, want 1", decisions)
	}
}

func TestDirectDecisionEntryIsNotRedactedButPreflighted(t *testing.T) {
	rec, _ := contentTestRecorder(t, "direct-secret")
	err := rec.Record(Entry{SessionID: "proxy", Type: decisionEntryType, Detail: map[string]any{"match_text": "direct-secret"}})
	if err == nil {
		t.Fatal("a direct decision entry with content must be refused, not redacted")
	}
}
