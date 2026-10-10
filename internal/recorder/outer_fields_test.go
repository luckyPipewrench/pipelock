// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

// entryFieldOrigin classifies every unencrypted recorder.Entry field by how
// the write boundary establishes it. A new field must be classified here.
var entryFieldOrigin = map[string]string{
	"Version":          "recorder-generated",
	"Sequence":         "recorder-generated",
	"Timestamp":        "recorder-generated",
	"PrevHash":         "recorder-generated",
	"Hash":             "recorder-generated",
	"RawRef":           "recorder-generated (caller value cleared)",
	"ChainKind":        "cleared",
	"WriterInstanceID": "cleared",
	"RawDetail":        "cleared, never serialized",
	"SessionID":        "bound to the acquired session; base validated at acquisition",
	"Detail":           "content boundary (bound projection or unattested preflight)",
	"Type":             "derived from the bound detail or scanned",
	"EventKind":        "derived from the bound detail or scanned",
	"Transport":        "derived from the bound detail or scanned",
	"Summary":          "derived from the bound detail or scanned",
	"TraceID":          "refused on producer-bound entries, scanned on unattested ones",
}

func TestEntryFieldsAreOriginOrScan(t *testing.T) {
	typ := reflect.TypeOf(Entry{})
	for i := 0; i < typ.NumField(); i++ {
		if _, ok := entryFieldOrigin[typ.Field(i).Name]; !ok {
			t.Errorf("recorder.Entry field %s has no origin-or-scan classification", typ.Field(i).Name)
		}
	}
	if typ.NumField() != len(entryFieldOrigin) {
		t.Errorf("classification lists %d fields, Entry has %d", len(entryFieldOrigin), typ.NumField())
	}
}

var outerTestProducer = receiptcontent.Register(receiptcontent.Schema{
	Kind:   "recorder.test.outer",
	Fields: map[string]receiptcontent.Class{"sig": receiptcontent.Generated, "note": receiptcontent.Content},
	Outer: func(detail []byte) (receiptcontent.Outer, error) {
		var d struct {
			Note string `json:"note"`
		}
		err := json.Unmarshal(detail, &d)
		return receiptcontent.Outer{Type: recorderTypeEvidenceReceipt, EventKind: "k", Summary: "note: " + d.Note}, err
	},
})

func TestBoundMirrorMustEqualProducerDerivation(t *testing.T) {
	// Round-2 C: a clean signed detail with a bound scan let a
	// detector-positive outer Summary through RecordWithReceiptScan.
	rec, _ := contentTestRecorder(t, "mirrorfixture")
	detail := []byte(`{"sig":"mirrorfixture-is-generated","note":"ok"}`)
	scan, err := rec.BindLifecycleContent(outerTestProducer, detail)
	if err != nil {
		t.Fatal(err)
	}
	base := Entry{SessionID: "proxy", Type: recorderTypeEvidenceReceipt, EventKind: "k", Summary: "note: ok", Detail: json.RawMessage(detail)}
	for name, mutate := range map[string]func(*Entry){
		"type":       func(e *Entry) { e.Type = recorderTypeReceipt },
		"summary":    func(e *Entry) { e.Summary = "mirrorfixture" },
		"transport":  func(e *Entry) { e.Transport = "x" },
		"event kind": func(e *Entry) { e.EventKind = "other" },
		"trace id":   func(e *Entry) { e.TraceID = "trace" },
	} {
		e := base
		mutate(&e)
		if err := rec.RecordWithReceiptScan(e, scan); !errors.Is(err, ErrOuterMismatch) {
			t.Fatalf("%s: err = %v, want ErrOuterMismatch", name, err)
		}
	}
	if err := rec.RecordWithReceiptScan(base, scan); err != nil {
		t.Fatalf("derived mirror refused: %v", err)
	}
}

func TestUnattestedMirrorIsScanned(t *testing.T) {
	rec, _ := contentTestRecorder(t, "mirrorfixture")
	detail := json.RawMessage(`{"note":"ok"}`)
	scan, err := rec.PreflightSignedReceiptDetail(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Entry{
		{SessionID: "proxy", Type: recorderTypeReceipt, Summary: "mirrorfixture", Detail: detail},
		{SessionID: "proxy", Type: recorderTypeReceipt, Transport: "mirror", Summary: "fixture", Detail: detail},
		{SessionID: "proxy", Type: recorderTypeReceipt, TraceID: "mirrorfixture", Detail: detail},
	} {
		if err := rec.RecordWithReceiptScan(e, &scan); !errors.Is(err, receiptcontent.ErrRejected) {
			t.Fatalf("unattested mirror %+v: err = %v, want content rejection", e, err)
		}
	}
}

func TestCallerRawRefIsCleared(t *testing.T) {
	rec, dir := contentTestRecorder(t, "never")
	if err := rec.Record(Entry{SessionID: "proxy", Type: "note", Summary: "s", Detail: map[string]any{"a": 1}, RawRef: "caller-chosen"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("evidence files: %v (found %d)", err, len(files))
	}
	entries, err := ReadEntries(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.RawRef != "" {
			t.Fatalf("caller RawRef persisted: %q", e.RawRef)
		}
	}
}

// The unattested bound path cannot carry an arbitrary Type: recordLocked
// dispatches it only for these exact, producer-defined evidence kinds.
func TestBoundEntryTypeIsClosed(t *testing.T) {
	for _, typ := range []string{recorderTypeReceipt, recorderTypeEvidenceReceipt, GroupGateEntryType, decisionEntryType, TranscriptRootEntryType} {
		if !isBoundEntryType(typ) {
			t.Fatalf("known bound Type %q not admitted", typ)
		}
	}
	for _, typ := range []string{"", "caller-secret", recorderTypeReceipt + "suffix", "prefix" + recorderTypeEvidenceReceipt} {
		if isBoundEntryType(typ) {
			t.Fatalf("caller-chosen Type %q admitted to the bound path", typ)
		}
	}
}
