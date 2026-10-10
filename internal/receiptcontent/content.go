// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package receiptcontent is the receipt content boundary. Every signed
// evidence kind registers a schema that classifies each JSON path of its
// detail. A projection keeps only the paths that can carry caller, agent,
// upstream, request, or operator text, and the scan views in views.go decide
// whether that projection may be persisted.
//
// Values a producer generates itself (chain hashes, signatures, signer keys,
// nonces, stamps) are excluded only through the producer's registered
// capability. The capability is the *Producer returned once by Register, so a
// field name or a value's spelling can never establish generated origin.
// Callers without that capability project every value as content.
//
// The package is a leaf: it imports the scanner only for its result type and
// combination iterator, so recorder and every evidence producer can import it
// without a cycle.
package receiptcontent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/digestorigin"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// Class says how one schema path of a receipt kind is treated.
type Class uint8

const (
	// Content is externally influenced text. It is projected and scanned; a
	// producer may redact a hit before signing.
	Content Class = iota + 1
	// Identity is projected and scanned but never redacted: redacting would
	// collapse distinct identities into one marker, so a hit rejects.
	Identity
	// Generated is produced by the registered producer itself. It is excluded
	// from the projection, including its whole subtree.
	Generated
	// Enum is excluded only when the value belongs to the schema's closed set;
	// any other value is Content.
	Enum
	// ProvenID is excluded only when the value carries this process's
	// generated-ID proof (see NewGeneratedID); any other value is Identity.
	ProvenID
	// Dynamic marks an object whose member names are caller data. Each member
	// name becomes a key atom, and member values use the schema path
	// "<path>.*".
	Dynamic
	// RunSession is a recorder session handle. When the value is a run
	// session whose suffix carries this process's proof (see
	// SplitProvenRunSession), only the operator base is projected, as an
	// Identity; the generated suffix is excluded. Any other value is Identity.
	RunSession
	// ComputedDigest is excluded only when the value (optionally labeled
	// "sha256:") is a digest this process computed (see digestorigin); any
	// other value, including a chosen 64-character hex string, is Content.
	ComputedDigest
	// ProvenRequestID accepts generated UUIDs and Guard correlation IDs whose
	// digest was computed locally. Every other value remains an Identity.
	ProvenRequestID
)

// Limits bound projection work before any expanded allocation. MaxDetailBytes
// equals the recorder's single-entry line limit; receipts are far below it.
const (
	MaxDetailBytes = 1 << 20
	maxDepth       = 64
	maxAtoms       = 4096
)

// OuterKey is the projection member that carries the recorder mirror fields
// (event kind, transport, summary), so their derived text is scanned in the
// same views as the detail it mirrors.
const OuterKey = "@outer"

// Outer holds the unencrypted recorder entry fields that mirror a detail.
type Outer struct {
	Type      string
	EventKind string
	Transport string
	Summary   string
}

// Schema classifies the JSON paths of one evidence kind. Object members join
// with ".", array elements append "[]", and Dynamic members use ".*". A path
// absent from Fields is Content, and an unclassified object is Dynamic, so an
// omission is scanned rather than skipped.
type Schema struct {
	Kind   string
	Fields map[string]Class
	Enums  map[string][]string
	// FixedValues names exact producer constants or retained operator values.
	// They remain in every content view except fragment reassembly. A changed
	// value stays a candidate. Only declared leaves may be listed here.
	FixedValues map[string][]string
	// Outer derives the recorder mirror fields from the exact detail bytes.
	// It must read only Content and Enum values; generated values in a mirror
	// would reintroduce detector input that the projection excludes.
	Outer func(detail []byte) (Outer, error)
}

// Producer is the capability to project one registered kind with its
// generated-field exclusions. Register creates the owning capability and
// refuses a second registration of the same kind. WithFixedValues derives
// narrower fragment searches from that capability.
type Producer struct {
	schema *Schema
	enums  map[string]map[string]struct{}
	fixed  map[string]map[string]struct{}
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Producer{}
)

// Register installs schema s and returns its producer capability. It panics
// on an empty kind, a duplicate kind, an Enum path without a value set, or
// invalid fixed-value declarations. These are programming errors caught at
// package initialization.
func Register(s Schema) *Producer {
	if s.Kind == "" {
		panic("receiptcontent: schema kind is required")
	}
	p := &Producer{schema: &Schema{Kind: s.Kind, Outer: s.Outer, Fields: map[string]Class{}}, enums: map[string]map[string]struct{}{}}
	for path, class := range s.Fields {
		if class < Content || class > ProvenRequestID {
			panic(fmt.Sprintf("receiptcontent: %s: invalid class for %q", s.Kind, path))
		}
		p.schema.Fields[path] = class
		if class != Enum {
			continue
		}
		values := s.Enums[path]
		if len(values) == 0 {
			panic(fmt.Sprintf("receiptcontent: %s: enum path %q has no values", s.Kind, path))
		}
		set := make(map[string]struct{}, len(values))
		for _, v := range values {
			set[v] = struct{}{}
		}
		p.enums[path] = set
	}
	p = p.WithFixedValues(s.FixedValues)
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[s.Kind]; dup {
		panic(fmt.Sprintf("receiptcontent: kind %q registered twice", s.Kind))
	}
	registry[s.Kind] = p
	return p
}

// WithFixedValues derives an immutable producer capability with additional
// exact fixed values. The owner supplies constants or retained configuration,
// never per-request text. This changes only fragment eligibility, not content
// scanning or redaction. Existing capabilities and the supplied map are not
// mutated; a different value at the same path remains a fragment candidate.
func (p *Producer) WithFixedValues(values map[string][]string) *Producer {
	fixed := make(map[string]map[string]struct{}, len(p.fixed)+len(values))
	for path, set := range p.fixed {
		fixed[path] = set // immutable sets may be shared
	}
	for path, list := range values {
		class, declared := p.schema.Fields[path]
		if !declared || (class != Content && class != Identity && class != RunSession) {
			panic(fmt.Sprintf("receiptcontent: %s: fixed values require a declared content leaf %q", p.Kind(), path))
		}
		set := make(map[string]struct{}, len(fixed[path])+len(list))
		for text := range fixed[path] {
			set[text] = struct{}{}
		}
		for _, text := range list {
			set[text] = struct{}{}
		}
		fixed[path] = set
	}
	return &Producer{schema: p.schema, enums: p.enums, fixed: fixed}
}

// Registered reports whether kind has a registered schema.
func Registered(kind string) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	_, ok := registry[kind]
	return ok
}

// Kinds returns the registered kinds in sorted order.
func Kinds() []string {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Kind returns the producer's registered kind.
func (p *Producer) Kind() string { return p.schema.Kind }

// Classification returns a copy of the producer's path classes, for registry
// completeness tests.
func (p *Producer) Classification() map[string]Class {
	out := make(map[string]Class, len(p.schema.Fields))
	for k, v := range p.schema.Fields {
		out[k] = v
	}
	return out
}

// Outer derives the mirror fields for detail with the registered function.
func (p *Producer) Outer(detail []byte) (Outer, error) {
	if p.schema.Outer == nil {
		return Outer{}, fmt.Errorf("receiptcontent: %s registers no outer derivation", p.schema.Kind)
	}
	return p.schema.Outer(detail)
}

// AtomKind distinguishes decoded values from caller-chosen member names.
type AtomKind uint8

const (
	AtomValue AtomKind = iota + 1
	AtomKey
)

// Atom is one decoded projection leaf. Path is the concrete JSON path, used
// to locate a value for redaction; under a Dynamic object it contains caller
// member names and must never be reported. Field is the schema path ("ext.*")
// and is safe to report. Text is the decoded value and must never be echoed.
type Atom struct {
	Path  string
	Field string
	Kind  AtomKind
	// Fixed is scanned but does not participate in fragment reassembly.
	Fixed    bool
	Identity bool
	Text     string
}

// Projection is the content-only view of one detail. It is immutable.
type Projection struct {
	kind       string
	atoms      []Atom
	structured []byte
	digest     [32]byte
}

// Kind returns the kind the projection was built for ("" when unproven).
func (p *Projection) Kind() string { return p.kind }

// Atoms returns a copy of the ordered atoms.
func (p *Projection) Atoms() []Atom { return append([]Atom(nil), p.atoms...) }

// Structured returns a copy of the canonical content-only JSON.
func (p *Projection) Structured() []byte { return append([]byte(nil), p.structured...) }

// Digest binds the projection: equal digests mean equal content, keys,
// identity classes, fragment eligibility, and mirror text.
func (p *Projection) Digest() [32]byte { return p.digest }

// Project builds the projection of detail under the producer's schema. When
// the schema derives outer fields they are added under OuterKey.
func (p *Producer) Project(detail []byte) (*Projection, error) {
	var outer *Outer
	if p.schema.Outer != nil {
		o, err := p.schema.Outer(detail)
		if err != nil {
			return nil, &RejectionError{Kind: p.schema.Kind, View: ViewMalformed, Reason: "outer fields cannot be derived"}
		}
		outer = &o
	}
	return project(p, detail, outer)
}

// ProjectUnproven builds the projection for a detail whose producer is not
// established: every value is Content and every member name is a key atom.
// outer, when non-nil, adds the caller's mirror fields as Content.
func ProjectUnproven(detail []byte, outer *Outer) (*Projection, error) {
	return project(nil, detail, outer)
}

type walker struct {
	p     *Producer
	atoms []Atom
}

func project(p *Producer, detail []byte, outer *Outer) (*Projection, error) {
	kind := ""
	if p != nil {
		kind = p.schema.Kind
	}
	reject := func(view View, reason string) error {
		return &RejectionError{Kind: kind, View: view, Reason: reason}
	}
	if len(detail) > MaxDetailBytes {
		return nil, reject(ViewBudget, fmt.Sprintf("detail exceeds %d bytes", MaxDetailBytes))
	}
	if err := jsonscan.RejectDuplicateKeys(detail); err != nil {
		return nil, reject(ViewMalformed, "detail has duplicate or invalid JSON members")
	}
	dec := json.NewDecoder(bytes.NewReader(detail))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, reject(ViewMalformed, "detail is not valid JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, reject(ViewMalformed, "detail has trailing data")
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, reject(ViewMalformed, "detail is not a JSON object")
	}
	w := &walker{p: p}
	tree, keep, err := w.walk(obj, "", "", 0)
	if err != nil {
		return nil, err
	}
	out, _ := tree.(map[string]any)
	if !keep || out == nil {
		out = map[string]any{}
	}
	if outer != nil {
		mirror := map[string]any{}
		for _, f := range []struct{ name, text string }{
			{"type", outer.Type}, {"event_kind", outer.EventKind}, {"transport", outer.Transport}, {"summary", outer.Summary},
		} {
			if f.text == "" {
				continue
			}
			mirror[f.name] = f.text
			w.atoms = append(w.atoms, Atom{Path: OuterKey + "." + f.name, Field: OuterKey + "." + f.name, Kind: AtomValue, Fixed: p != nil, Text: f.text})
		}
		if len(mirror) > 0 {
			out[OuterKey] = mirror
		}
	}
	if len(w.atoms) > maxAtoms {
		return nil, reject(ViewBudget, fmt.Sprintf("projection exceeds %d atoms", maxAtoms))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, reject(ViewMalformed, "projection cannot be encoded")
	}
	structured := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	h := sha256.New()
	_, _ = h.Write(structured)
	for _, a := range w.atoms {
		// Identity is part of the binding: the same text under a different
		// class must not satisfy a prior scan's redaction decision. Fragment
		// eligibility is also bound, so a scan under a narrower search cannot
		// attest a projection with a wider search.
		_, _ = fmt.Fprintf(h, "\x00%s\x00%d\x00%t\x00%t", a.Path, a.Kind, a.Identity, a.Fixed)
	}
	proj := &Projection{kind: kind, atoms: w.atoms, structured: structured}
	copy(proj.digest[:], h.Sum(nil))
	return proj, nil
}

func (w *walker) class(schemaPath string) (Class, bool) {
	if w.p == nil {
		return 0, false
	}
	c, ok := w.p.schema.Fields[schemaPath]
	return c, ok
}

func joinPath(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "." + name
}

func (w *walker) walk(v any, schemaPath, path string, depth int) (any, bool, error) {
	kind := ""
	if w.p != nil {
		kind = w.p.schema.Kind
	}
	if depth > maxDepth {
		return nil, false, &RejectionError{Kind: kind, View: ViewBudget, Path: path, Reason: fmt.Sprintf("detail nests deeper than %d", maxDepth)}
	}
	if len(w.atoms) > maxAtoms {
		return nil, false, &RejectionError{Kind: kind, View: ViewBudget, Reason: fmt.Sprintf("projection exceeds %d atoms", maxAtoms)}
	}
	class, classified := w.class(schemaPath)
	if classified && class == Generated && path != "" {
		return nil, false, nil
	}
	switch val := v.(type) {
	case map[string]any:
		// A proven kind's root has fixed member names; any other unclassified
		// object is treated as caller data so an omission is still scanned.
		provenRoot := w.p != nil && path == ""
		dynamic := (!classified && !provenRoot) || class == Dynamic
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(val))
		for _, k := range keys {
			childPath := joinPath(path, k)
			childSchema := joinPath(schemaPath, k)
			// Only a declared member of a fixed object inherits its schema
			// class. A name carrying a path metacharacter ("a.b" could alias
			// the nested path a -> b) or an undeclared name is caller data.
			if !dynamic && w.p != nil {
				if _, declared := w.p.schema.Fields[childSchema]; !declared || strings.ContainsAny(k, ".[]*") {
					w.atoms = append(w.atoms, Atom{Path: childPath, Field: joinPath(schemaPath, "*"), Kind: AtomKey, Text: k})
					childSchema = joinPath(schemaPath, "*")
				}
			}
			if dynamic {
				childSchema = joinPath(schemaPath, "*")
				w.atoms = append(w.atoms, Atom{Path: childPath, Field: joinPath(schemaPath, "*"), Kind: AtomKey, Text: k})
			}
			child, keep, err := w.walk(val[k], childSchema, childPath, depth+1)
			if err != nil {
				return nil, false, err
			}
			switch {
			case keep:
				out[k] = child
			case dynamic:
				out[k] = nil // the member name itself is content
			}
		}
		return out, len(out) > 0, nil
	case []any:
		out := make([]any, 0, len(val))
		for i, elem := range val {
			child, keep, err := w.walk(elem, schemaPath+"[]", path+"["+strconv.Itoa(i)+"]", depth+1)
			if err != nil {
				return nil, false, err
			}
			if keep {
				out = append(out, child)
			}
		}
		return out, len(out) > 0, nil
	case string:
		return w.leaf(val, val, schemaPath, path, class, classified)
	case json.Number:
		return w.leaf(val, val.String(), schemaPath, path, class, classified)
	case bool:
		// One bit cannot carry a token; keep it for structured context only.
		return val, true, nil
	default: // JSON null
		return nil, false, nil
	}
}

func (w *walker) leaf(v any, text, schemaPath, path string, class Class, classified bool) (any, bool, error) {
	identity := false
	if classified {
		switch class {
		case Enum:
			if _, ok := w.p.enums[schemaPath][text]; ok {
				return nil, false, nil
			}
		case ProvenID, ProvenRequestID:
			if class == ProvenRequestID {
				if digest, ok := strings.CutPrefix(text, "guard-exec:"); ok && digestorigin.Computed(digest) {
					return nil, false, nil
				}
			}
			if VerifyGeneratedID(text) {
				return nil, false, nil
			}
			identity = true
		case Identity:
			identity = true
		case ComputedDigest:
			if digestorigin.Computed(strings.TrimPrefix(text, "sha256:")) {
				return nil, false, nil
			}
		case RunSession:
			// The structured view keeps the base too, so the generated
			// suffix never reaches any detector view.
			if base, ok := SplitProvenRunSession(text); ok {
				v, text = base, base
			}
			identity = true
		}
	}
	if text == "" {
		return v, true, nil
	}
	fixed := false
	if classified && w.p != nil {
		_, fixed = w.p.fixed[schemaPath][text]
	}
	w.atoms = append(w.atoms, Atom{Path: path, Field: schemaPath, Kind: AtomValue, Identity: identity, Fixed: fixed, Text: text})
	return v, true, nil
}
