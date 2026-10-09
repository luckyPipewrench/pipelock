// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func atomPaths(p *Projection) map[string]Atom {
	out := map[string]Atom{}
	for _, a := range p.Atoms() {
		out[a.Path] = a
	}
	return out
}

func TestProjectClassifiesPaths(t *testing.T) {
	gen := NewGeneratedID().String()
	chosen := uuid.Must(uuid.NewV7()).String()
	detail := []byte(`{"version":1,"signature":"ed25519:abcd","crypto":{"k":"v"},"id":"` + gen + `",` +
		`"parent":"` + chosen + `","verdict":"allow","note":"hello","list":["a","b"],"nested":{"x":"y"},` +
		`"ext":{"dyn":"val","drop":null},"big":12345678901234567890,"flag":true}`)
	p, err := testProducer.Project(detail)
	if err != nil {
		t.Fatal(err)
	}
	got := atomPaths(p)
	for _, excluded := range []string{"version", "signature", "crypto.k", "id", "verdict"} {
		if _, ok := got[excluded]; ok {
			t.Fatalf("%s must be excluded", excluded)
		}
	}
	if a := got["parent"]; !a.Identity || a.Text != chosen {
		t.Fatalf("chosen UUID must stay an identity atom: %+v", a)
	}
	if a := got["big"]; a.Text != "12345678901234567890" {
		t.Fatalf("numbers must keep their exact text: %+v", a)
	}
	if a := got["ext.dyn"]; a.Kind != AtomKey || a.Text != "dyn" {
		// the key atom and the value atom share a path; the map keeps the last
		_ = a
	}
	keys := 0
	for _, a := range p.Atoms() {
		if a.Kind == AtomKey {
			keys++
		}
	}
	if keys != 5 { // ext.dyn, ext.drop, and the undeclared nested.x, big, flag
		t.Fatalf("caller member names = %d, want 5", keys)
	}
	s := string(p.Structured())
	for _, want := range []string{`"@outer":{"summary":"test: allow","type":"test"}`, `"drop":null`, `"flag":true`, `"nested":{"x":"y"}`} {
		if !strings.Contains(s, want) {
			t.Fatalf("structured %s missing %s", s, want)
		}
	}
	if strings.Contains(s, "ed25519") || strings.Contains(s, gen) {
		t.Fatalf("structured view leaked a generated value: %s", s)
	}
	if p.Kind() != "test.kind" {
		t.Fatal("kind")
	}
}

func TestProjectChosenUUIDInProvenIDFieldIsIdentity(t *testing.T) {
	// Round-2 A: a caller-chosen canonical UUIDv7 is format-valid but has no
	// origin proof, so it stays projected and is never redacted.
	chosen := uuid.Must(uuid.NewV7()).String()
	p, err := testProducer.Project([]byte(`{"id":"` + chosen + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := atomPaths(p)["id"]; !ok || !a.Identity {
		t.Fatalf("chosen UUID in a ProvenID field = %+v, %v; want identity atom", a, ok)
	}
}

func TestProjectMemberNameCannotAliasGeneratedPath(t *testing.T) {
	// A root member literally named "nested.gen" joins to the same schema
	// path as nested -> gen (Generated). It must stay caller content.
	p, err := testProducer.Project([]byte(`{"nested.gen":"aliased","nested":{"gen":"real"}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := atomPaths(p)
	if a, ok := got["nested.gen"]; !ok || a.Text == "real" {
		t.Fatalf("aliased member must be projected as content, got %+v %v", a, ok)
	}
	for _, a := range p.Atoms() {
		if a.Text == "real" {
			t.Fatal("the declared generated member must stay excluded")
		}
	}
}

func TestProjectNonMemberEnumIsContent(t *testing.T) {
	p, err := testProducer.Project([]byte(`{"verdict":"custom-verdict"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atomPaths(p)["verdict"]; !ok {
		t.Fatal("a value outside the closed set must be projected")
	}
}

func TestProjectDigestBindsContentOnly(t *testing.T) {
	a, _ := testProducer.Project([]byte(`{"signature":"one","note":"n"}`))
	b, _ := testProducer.Project([]byte(`{"signature":"two","note":"n"}`))
	c, _ := testProducer.Project([]byte(`{"signature":"one","note":"m"}`))
	if a.Digest() != b.Digest() {
		t.Fatal("generated fields must not change the content digest")
	}
	if a.Digest() == c.Digest() {
		t.Fatal("content change must change the digest")
	}
	d, _ := testProducer.Project([]byte(`{"parent":"n"}`))
	e, _ := testProducer.Project([]byte(`{"note":"n"}`))
	if d.Digest() == e.Digest() {
		t.Fatal("digest must bind field paths and classes")
	}
}

func TestProjectUnprovenScansEverything(t *testing.T) {
	p, err := ProjectUnproven([]byte(`{"signature":"s","version":1,"o":{"k":"v"}}`), &Outer{Summary: "sum", Transport: "t"})
	if err != nil {
		t.Fatal(err)
	}
	got := atomPaths(p)
	for _, want := range []string{"signature", "version", "o.k", "@outer.summary", "@outer.transport"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("unproven projection missing %s: %v", want, got)
		}
	}
	if p.Kind() != "" {
		t.Fatal("unproven kind")
	}
}

func TestProjectRejectsMalformedAndOversized(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxDepth+2) + `1` + strings.Repeat(`}`, maxDepth+2)
	many := `{"list":[` + strings.TrimSuffix(strings.Repeat(`"x",`, maxAtoms+1), ",") + `]}`
	cases := map[string]struct {
		in   string
		view View
	}{
		"duplicate":  {`{"a":1,"a":2}`, ViewMalformed},
		"invalid":    {`{"a":`, ViewMalformed},
		"trailing":   {`{"a":1} {}`, ViewMalformed},
		"not object": {`["a"]`, ViewMalformed},
		"too large":  {`{"a":"` + strings.Repeat("x", MaxDetailBytes) + `"}`, ViewBudget},
		"too deep":   {deep, ViewBudget},
		"too many":   {many, ViewBudget},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ProjectUnproven([]byte(tc.in), nil)
			var rej *RejectionError
			if !errors.As(err, &rej) || rej.View != tc.view || !errors.Is(err, ErrRejected) {
				t.Fatalf("err = %v, want %s rejection", err, tc.view)
			}
		})
	}
}

func TestProjectOuterDerivationFailureRejects(t *testing.T) {
	_, err := testProducer.Project([]byte(`{"verdict":7}`))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want rejection when outer fields cannot be derived", err)
	}
	if _, err := testProducer.Outer([]byte(`{"verdict":"block"}`)); err != nil {
		t.Fatal(err)
	}
	bare := Register(Schema{Kind: "test.no-outer"})
	if _, err := bare.Outer(nil); err == nil {
		t.Fatal("missing outer derivation must error")
	}
	if _, err := bare.Project([]byte(`{"a":"b"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterContract(t *testing.T) {
	for name, s := range map[string]Schema{
		"empty kind": {},
		"duplicate":  {Kind: "test.kind"},
		"bad class":  {Kind: "test.bad-class", Fields: map[string]Class{"a": 0}},
		"enum empty": {Kind: "test.bad-enum", Fields: map[string]Class{"a": Enum}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Register must panic")
				}
			}()
			Register(s)
		})
	}
	if !Registered("test.kind") || Registered("test.missing") {
		t.Fatal("Registered")
	}
	found := false
	for _, k := range Kinds() {
		found = found || k == "test.kind"
	}
	if !found || testProducer.Kind() != "test.kind" {
		t.Fatal("Kinds")
	}
	cls := testProducer.Classification()
	cls["note"] = Generated
	if testProducer.Classification()["note"] != Content {
		t.Fatal("Classification must return a copy")
	}
}

func TestGeneratedIDProof(t *testing.T) {
	id := NewGeneratedID().String()
	if !VerifyGeneratedID(id) {
		t.Fatal("minted ID must verify")
	}
	tampered := []byte(id)
	if tampered[35] == '0' {
		tampered[35] = '1'
	} else {
		tampered[35] = '0'
	}
	for name, s := range map[string]string{
		"tampered":   string(tampered),
		"uppercase":  strings.ToUpper(id),
		"chosen v7":  uuid.Must(uuid.NewV7()).String(),
		"chosen v4":  uuid.NewString(),
		"not a uuid": strings.Repeat("a", 36),
		"short":      "abc",
	} {
		if VerifyGeneratedID(s) {
			t.Fatalf("%s must not verify", name)
		}
	}
	if (GeneratedID{}).String() != "" {
		t.Fatal("zero value")
	}
}

func TestRedactValues(t *testing.T) {
	out, err := testProducer.RedactValues([]byte(`{"note":"secret","list":["a","b"],"n":1}`), []string{"note", "list[1]"}, func(path, _ string) string {
		return "[REDACTED:" + path + "]"
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"list":["a","[REDACTED:list[1]]"],"n":1,"note":"[REDACTED:note]"}` {
		t.Fatalf("redacted = %s", out)
	}
	for name, tc := range map[string]struct {
		in   string
		path string
	}{
		"number": {`{"n":1}`, "n"},
		"absent": {`{"n":1}`, "missing"},
	} {
		if _, err := testProducer.RedactValues([]byte(tc.in), []string{tc.path}, func(_, v string) string { return v }); !errors.Is(err, ErrRejected) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if _, err := testProducer.RedactValues([]byte(`{`), nil, nil); !errors.Is(err, ErrRejected) {
		t.Fatal("invalid JSON must reject")
	}
}
