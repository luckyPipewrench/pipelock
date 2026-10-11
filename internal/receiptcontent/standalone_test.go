// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func standaloneProducers() (standalone, content *Producer) {
	fields := func(line Class) map[string]Class {
		return map[string]Class{"a": Content, "line": line, "m": Content, "z": Content}
	}
	return &Producer{schema: &Schema{Kind: "test.standalone", Fields: fields(Standalone)}},
		&Producer{schema: &Schema{Kind: "test.standalone_content", Fields: fields(Content)}}
}

// TestStandaloneStaysInEveryViewButFragments keeps a Standalone value in the
// atom, structured and joined views, and out of fragment reassembly only.
func TestStandaloneStaysInEveryViewButFragments(t *testing.T) {
	standalone, content := standaloneProducers()
	raw := []byte(`{"a":"left","line":"status=200","m":"mid","z":"right"}`)
	p, err := standalone.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := content.Project(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() == cp.Digest() {
		t.Fatal("standalone participation must be bound by the digest")
	}
	for _, a := range p.Atoms() {
		if a.Field == "line" && (!a.Standalone || a.Fixed || a.Identity) {
			t.Fatalf("line atom = %+v, want standalone content", a)
		}
	}
	for _, tc := range []struct {
		name string
		text string
		view View
	}{
		{"alone", "status=200", ViewAtom},
		{"structured", string(p.Structured()), ViewStructured},
		{"joined in projection order", "leftstatus=200midright", ViewValues},
		{"other fields still reassemble", "rightleft", ViewFragments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			det := func(_ context.Context, text string) scanner.TextDLPResult {
				return scanner.TextDLPResult{Clean: text != tc.text}
			}
			rep, err := Scan(t.Context(), det, p)
			requireView(t, rep, err, tc.view)
		})
	}
	if rep, err := Scan(t.Context(), func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "status=200"}
	}, p); err != nil || !rep.Redactable() {
		t.Fatalf("a standalone hit must stay redactable content: %+v %v", rep.Findings, err)
	}

	// The traded split: the line with a field it does not neighbor.
	split := func(_ context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: text != "rightstatus=200"}
	}
	if rep, err := Scan(t.Context(), split, cp); err != nil || rep.Clean() {
		t.Fatalf("as content the split must be found: %+v %v", rep.Findings, err)
	}
	var texts []string
	record := func(_ context.Context, text string) scanner.TextDLPResult {
		texts = append(texts, text)
		return scanner.TextDLPResult{Clean: true}
	}
	if _, err := Scan(t.Context(), record, p); err != nil {
		t.Fatal(err)
	}
	for _, text := range texts {
		if text == "rightstatus=200" || text == "status=200left" {
			t.Fatalf("standalone value built into fragment %q", text)
		}
	}
	if rep, err := Scan(t.Context(), split, p); err != nil || !rep.Clean() {
		t.Fatalf("standalone split must be the declared loss: %+v %v", rep.Findings, err)
	}
}

func TestProvenRequestIDAcceptsOnlyMintedProxyIDs(t *testing.T) {
	prod := &Producer{schema: &Schema{Kind: "test.request_id", Fields: map[string]Class{"id": ProvenRequestID}}}
	minted := NewRequestID()
	if !strings.HasPrefix(minted, RequestIDPrefix) || !VerifyGeneratedID(strings.TrimPrefix(minted, RequestIDPrefix)) {
		t.Fatalf("minted request ID %q carries no proof", minted)
	}
	bare := NewGeneratedID().String()
	foreign := "req-01a12bcb-6bb0-7e78-8522-f69bdaf2e4c0"
	for _, tc := range []struct {
		id       string
		excluded bool
	}{
		{minted, true},
		{bare, true},
		{"req-12", false},
		{foreign, false},
		{RequestIDPrefix + RequestIDPrefix + strings.TrimPrefix(minted, RequestIDPrefix), false},
		{strings.ToUpper(minted), false},
		{minted + "x", false},
		{" " + minted, false},
	} {
		p, err := prod.Project([]byte(`{"id":"` + tc.id + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		atoms := p.Atoms()
		if tc.excluded && len(atoms) != 0 {
			t.Fatalf("%q: minted ID projected", tc.id)
		}
		if !tc.excluded && (len(atoms) != 1 || !atoms[0].Identity) {
			t.Fatalf("%q: unminted ID must stay an identity, got %+v", tc.id, atoms)
		}
	}
}
