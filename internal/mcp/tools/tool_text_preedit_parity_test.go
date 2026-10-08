// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// These tests prove CONDITIONAL equivalence: given an identical per-visit map
// iteration schedule, the sink-based extraction emits exactly the bytes the
// pre-edit extraction emitted. They say nothing about two independently
// randomized traversals, and nothing about whether any text is safe.

// preEditOracleHashes are the SHA-256 digests of the six extraction functions
// at 7616d601b, taken from git show before any edit.
var preEditOracleHashes = map[string]string{
	"collectSchemaValueText":    "5dfb6f8cb42509e3fddbc51fc5ff9f5cea064ba0d0db1f887f9906ae439ab572",
	"collectAllSchemaText":      "e030830846f5f810279ed919de1f5f16bec7a6141b0bc685ac8e23a3694dfaac",
	"collectStringLeaves":       "d69f71d131983a74c9a20892a95c42e5fce5009a9b173722789bc0f69bed2dcd",
	"ExtractSchemaDescriptions": "8dedde7f974d87f74dc20eb48cc361a705b378306eb8c5777bee91ef436ec113",
	"extractToolText":           "c2100d7fa9c5362639b98e8489126dbe073c202fc2f2b50e34a1de5ff34937e7",
	"extractToolGeneralText":    "ac50c1c9c02723ed2fe1de4921fa715709fc3c99bbbeb55b0be7535ecec378e5",
}

func TestPreEditOracleIsVerbatim(t *testing.T) {
	src, err := os.ReadFile("tool_text_preedit_oracle_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	// Reverse the declared iterator adaptation, then the renames.
	body = strings.ReplaceAll(body,
		"case map[string]interface{}:\n\t\tfor _, key := range preKeyOrder(val) {\n\t\t\tchild := val[key]",
		"case map[string]interface{}:\n\t\tfor _, child := range val {")
	body = strings.ReplaceAll(body,
		"for _, key := range preKeyOrder(obj) {\n\t\tv := obj[key]",
		"for key, v := range obj {")
	if strings.Count(body, "preKeyOrder(") != 0 {
		t.Fatal("oracle uses preKeyOrder outside the two declared map ranges")
	}
	for name := range preEditOracleHashes {
		body = regexp.MustCompile(`\bpre`+strings.ToUpper(name[:1])+name[1:]+`\(`).ReplaceAllString(body, name+"(")
	}
	for name, want := range preEditOracleHashes {
		start := strings.Index(body, "func "+name+"(")
		if start < 0 {
			t.Fatalf("oracle lacks %s", name)
		}
		end := strings.Index(body[start:], "\n}\n")
		sum := sha256.Sum256([]byte(body[start : start+end+2]))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s differs from 7616d601b: sha256 %s, want %s", name, got, want)
		}
	}
}

// preEditScanText is the detector input composition ScanTools used at
// 7616d601b, over the frozen oracle functions.
func preEditScanText(tool ToolDef) string {
	return strings.Trim(strings.Join([]string{preExtractToolText(tool), preExtractToolGeneralText(tool)}, ". "), ". ")
}

func sortedObjKeys(obj map[string]interface{}) []string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// scheduledVisit is one map visit: its ordinal in the walk, a canonical
// fingerprint of the whole object (keys and values), and the order the walk
// takes its keys in. Binding the full fingerprint means two maps with the same
// keys but different contents cannot be swapped or revisited undetected.
type scheduledVisit struct {
	ordinal     int
	fingerprint string
	keys        []string
}

func objectFingerprint(obj map[string]interface{}) string {
	// encoding/json writes map keys sorted, so this is canonical.
	b, err := json.Marshal(obj)
	if err != nil {
		return "unmarshalable:" + err.Error()
	}
	return string(b)
}

// checkPermutation requires keys to be exactly the keys of obj: same length,
// no duplicates, no unknown keys, so none missing.
func checkPermutation(keys []string, obj map[string]interface{}) error {
	if len(keys) != len(obj) {
		return fmt.Errorf("schedule has %d keys, object has %d", len(keys), len(obj))
	}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if seen[k] {
			return fmt.Errorf("schedule repeats key %q", k)
		}
		seen[k] = true
		if _, ok := obj[k]; !ok {
			return fmt.Errorf("schedule names unknown key %q", k)
		}
	}
	return nil
}

// scheduleRecorder chooses a permutation for every map visit the oracle makes
// and records it. choose receives the visit ordinal and the sorted keys.
type scheduleRecorder struct {
	choose func(ordinal int, sorted []string) []string
	visits []scheduledVisit
	err    error
}

func (r *scheduleRecorder) order(obj map[string]interface{}) []string {
	keys := r.choose(len(r.visits), sortedObjKeys(obj))
	if err := checkPermutation(keys, obj); err != nil && r.err == nil {
		r.err = fmt.Errorf("recorded visit %d: %w", len(r.visits), err)
	}
	r.visits = append(r.visits, scheduledVisit{ordinal: len(r.visits), fingerprint: objectFingerprint(obj), keys: slices.Clone(keys)})
	return slices.Clone(keys)
}

// scheduleReplayer hands the recorded schedule to the new walker and fails on
// any divergence: an unexpected visit, a visit out of ordinal sequence, a
// different object, a key list that is not an exact permutation, or entries
// left over. It never falls back to another order.
type scheduleReplayer struct {
	visits []scheduledVisit
	pos    int
	err    error
}

func (p *scheduleReplayer) order(obj map[string]interface{}) []string {
	if p.err != nil {
		return nil
	}
	if p.pos >= len(p.visits) {
		p.err = fmt.Errorf("unexpected visit %d beyond the %d scheduled", p.pos, len(p.visits))
		return nil
	}
	v := p.visits[p.pos]
	switch {
	case v.ordinal != p.pos:
		p.err = fmt.Errorf("visit %d replayed schedule entry %d", p.pos, v.ordinal)
	case objectFingerprint(obj) != v.fingerprint:
		p.err = fmt.Errorf("visit %d reached a different object than scheduled", p.pos)
	default:
		if err := checkPermutation(v.keys, obj); err != nil {
			p.err = fmt.Errorf("visit %d: %w", p.pos, err)
		}
	}
	if p.err != nil {
		return nil
	}
	p.pos++
	return slices.Clone(v.keys)
}

func (p *scheduleReplayer) finish() error {
	if p.err != nil {
		return p.err
	}
	if p.pos != len(p.visits) {
		return fmt.Errorf("%d scheduled visits never happened", len(p.visits)-p.pos)
	}
	return nil
}

func nthPermutation(sorted []string, n int) []string {
	pool := slices.Clone(sorted)
	out := make([]string, 0, len(pool))
	for len(pool) > 0 {
		f := factorial(len(pool) - 1)
		i := n / f
		n %= f
		out = append(out, pool[i])
		pool = slices.Delete(pool, i, i+1)
	}
	return out
}

func factorial(n int) int {
	f := 1
	for i := 2; i <= n; i++ {
		f *= i
	}
	return f
}

// compareUnderSchedule runs the oracle with choose, replays the recorded
// schedule into the new walker, and requires byte-identical detector input.
// It returns the schedule and the new walker's output for span checks.
func compareUnderSchedule(t *testing.T, label string, tool ToolDef, choose func(int, []string) []string) ([]scheduledVisit, string, []toolTextSpan) {
	t.Helper()
	rec := &scheduleRecorder{choose: choose}
	preKeyOrder = rec.order
	want := preEditScanText(tool)
	preKeyOrder = nil
	if rec.err != nil {
		t.Fatalf("%s: %v", label, rec.err)
	}

	rep := &scheduleReplayer{visits: rec.visits}
	got, spans := toolScanTextOrdered(tool, rep.order)
	if err := rep.finish(); err != nil {
		t.Fatalf("%s: schedule divergence: %v", label, err)
	}
	if got != want {
		t.Fatalf("%s: detector input differs\n new: %q\n pre: %q", label, got, want)
	}
	return rec.visits, got, spans
}

// forEachExhaustiveSchedule enumerates every combination of permutations over
// every map visit, with radices discovered as the walk reaches each visit.
func forEachExhaustiveSchedule(t *testing.T, limit int, run func(choose func(int, []string) []string)) int {
	t.Helper()
	var digits, radices []int
	runs := 0
	for {
		runs++
		if runs > limit {
			t.Fatalf("exhaustive schedule exceeds %d runs; shrink the fixture", limit)
		}
		used := 0
		run(func(ordinal int, sorted []string) []string {
			used = ordinal + 1
			if ordinal == len(digits) {
				digits = append(digits, 0)
				radices = append(radices, factorial(len(sorted)))
			}
			return nthPermutation(sorted, digits[ordinal])
		})
		digits, radices = digits[:used], radices[:used]
		k := len(digits) - 1
		for k >= 0 {
			digits[k]++
			if digits[k] < radices[k] {
				break
			}
			k--
		}
		if k < 0 {
			return runs
		}
		digits, radices = digits[:k+1], radices[:k+1]
	}
}

func seededChooser(seed uint64) func(int, []string) []string {
	return func(ordinal int, sorted []string) []string {
		r := rand.New(rand.NewPCG(seed, uint64(ordinal))) //nolint:gosec // G404: deterministic test schedule, not security-sensitive
		out := slices.Clone(sorted)
		r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		return out
	}
}

func mustTool(t *testing.T, raw string) ToolDef {
	t.Helper()
	var tool ToolDef
	if err := json.Unmarshal([]byte(raw), &tool); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return tool
}

// controlledOrderFixtures keep every object small enough to enumerate every
// permutation of every visit.
var controlledOrderFixtures = []struct {
	name, raw string
	pointers  []string // sorted; nil means "same as the first schedule"
}{
	{"multi-key properties", `{"name":"f","description":"d","inputSchema":{"type":"object","properties":{
		"a":{"description":"A","title":"At"},"b":{"description":"B","pattern":"Bp"},"c":{"$comment":"C"}}}}`, nil},
	{"repeated identical subtrees", `{"name":"f","inputSchema":{"allOf":[{"p":"x","q":"y"},{"p":"x","q":"y"},{"p":"x","q":"y"}]}}`, nil},
	{"nested default and const maps", `{"name":"f","inputSchema":{"default":{"p":"1","q":"2","r":{"s":"3","t":"4"}},"const":{"u":"5","v":"6"}}}`, nil},
	{"examples enum and extensions", `{"name":"f","inputSchema":{"examples":[{"k":"e1","l":"e2"},"e3"],"enum":["n1",{"m":"n2","o":"n3"}],"x-vendor":{"g":"x1","h":["x2","x3"]}}}`, nil},
	{"unmodelled, type keyword, empty, null, numbers", `{"name":"f","inputSchema":{"instructions":"read me","note":"string","title":"","nothing":null,"n":3,"empty":{},"list":[]}}`, nil},
	{"duplicate equal strings in different fields", `{"name":"f","description":"same","inputSchema":{"description":"same","properties":{"a":{"description":"same"},"b":{"title":"same"}},"enum":["same","same"]}}`, []string{
		"/description", "/inputSchema/description", "/inputSchema/enum/0", "/inputSchema/enum/1",
		"/inputSchema/properties/a/description", "/inputSchema/properties/b/title",
	}},
	{"full tool every surface", `{"name":"full_tool","title":"Full","description":"Top.","inputSchema":{"properties":{"a":{"description":"in a"},"b":{"description":"in b"}}},
		"outputSchema":{"properties":{"r":{"description":"out r"},"s":{"title":"out s"}}},"annotations":{"title":"ann","hint":"h"},"_meta":{"k":"meta one","j":"meta two"},"x-extra":{"y":"unknown one","z":"unknown two"}}`, nil},
	{"seven sibling keys", `{"name":"f","inputSchema":{"properties":{"k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7"}}}`, nil},
}

// TestControlledOrderExhaustiveFixtures runs every permutation of every visit.
// Under each schedule it requires the oracle's bytes, the span layout, the
// fixture's exact pointer multiset where declared (and otherwise the same
// multiset as the first schedule), and full marker provenance.
func TestControlledOrderExhaustiveFixtures(t *testing.T) {
	for _, fx := range controlledOrderFixtures {
		t.Run(fx.name, func(t *testing.T) {
			tool := mustTool(t, fx.raw)
			want := fx.pointers
			runs := forEachExhaustiveSchedule(t, 20000, func(choose func(int, []string) []string) {
				visits, text, spans := compareUnderSchedule(t, fx.name, tool, choose)
				checkSpanLayout(t, text, spans)
				got := spanPointers(spans)
				if want == nil {
					want = got
				}
				if !slices.Equal(got, want) {
					t.Fatalf("pointers %v, want %v", got, want)
				}
				checkSpanProvenance(t, fx.raw, visits, spans)
			})
			if runs < 2 {
				t.Fatalf("fixture ran %d schedule(s); it exercises no ordering", runs)
			}
		})
	}
}

// TestControlledOrderRepeatedVisitsGetDistinctSchedules pins that the repeated
// identical subtrees really are visited separately and can be scheduled
// differently, so per-visit replay is what is being exercised.
func TestControlledOrderRepeatedVisitsGetDistinctSchedules(t *testing.T) {
	tool := mustTool(t, controlledOrderFixtures[1].raw)
	distinct := false
	forEachExhaustiveSchedule(t, 100, func(choose func(int, []string) []string) {
		visits, _, _ := compareUnderSchedule(t, "repeated", tool, choose)
		if len(visits) != 4 {
			t.Fatalf("visits = %d, want the root plus three subtrees", len(visits))
		}
		if !slices.Equal(visits[1].keys, visits[2].keys) || !slices.Equal(visits[2].keys, visits[3].keys) {
			distinct = true
		}
	})
	if !distinct {
		t.Fatal("no schedule gave the repeated subtrees different orders")
	}
}

func recordSchedule(t *testing.T, tool ToolDef, choose func(int, []string) []string) []scheduledVisit {
	t.Helper()
	rec := &scheduleRecorder{choose: choose}
	preKeyOrder = rec.order
	_ = preEditScanText(tool)
	preKeyOrder = nil
	if rec.err != nil {
		t.Fatal(rec.err)
	}
	return rec.visits
}

func replayErr(tool ToolDef, visits []scheduledVisit) error {
	rep := &scheduleReplayer{visits: visits}
	toolScanTextOrdered(tool, rep.order)
	return rep.finish()
}

func TestControlledOrderScheduleDivergenceFails(t *testing.T) {
	tool := mustTool(t, controlledOrderFixtures[0].raw)
	visits := recordSchedule(t, tool, seededChooser(1))
	if err := replayErr(tool, visits); err != nil {
		t.Fatalf("faithful replay failed: %v", err)
	}
	// The root object, then the properties object, then a, b, c.
	if len(visits) < 3 || len(visits[1].keys) != 3 {
		t.Fatalf("fixture shape changed: %d visits", len(visits))
	}
	mutate := func(f func(v []scheduledVisit) []scheduledVisit) []scheduledVisit {
		c := make([]scheduledVisit, len(visits))
		for i, v := range visits {
			c[i] = scheduledVisit{ordinal: v.ordinal, fingerprint: v.fingerprint, keys: slices.Clone(v.keys)}
		}
		return f(c)
	}
	for name, bad := range map[string][]scheduledVisit{
		"leftover entry": mutate(func(v []scheduledVisit) []scheduledVisit {
			return append(v, scheduledVisit{ordinal: len(v), fingerprint: "{}"})
		}),
		"unscheduled visit": mutate(func(v []scheduledVisit) []scheduledVisit { return v[:len(v)-1] }),
		"missing key":       mutate(func(v []scheduledVisit) []scheduledVisit { v[1].keys = v[1].keys[:2]; return v }),
		"duplicate key": mutate(func(v []scheduledVisit) []scheduledVisit {
			v[1].keys[2] = v[1].keys[0]
			return v
		}),
		"unknown key":     mutate(func(v []scheduledVisit) []scheduledVisit { v[1].keys[2] = "zz"; return v }),
		"wrong object":    mutate(func(v []scheduledVisit) []scheduledVisit { v[1].fingerprint = v[2].fingerprint; return v }),
		"ordinal skipped": mutate(func(v []scheduledVisit) []scheduledVisit { v[2].ordinal = 3; return v }),
	} {
		if replayErr(tool, bad) == nil {
			t.Errorf("%s: replay accepted a divergent schedule", name)
		}
	}
	// The recorder enforces the same permutation rule on what it hands out.
	for name, keys := range map[string]func([]string) []string{
		"missing":   func(k []string) []string { return k[:len(k)-1] },
		"duplicate": func(k []string) []string { return append(k[:len(k)-1:len(k)-1], k[0]) },
		"unknown":   func(k []string) []string { return append(slices.Clone(k[:len(k)-1]), "zz") },
	} {
		rec := &scheduleRecorder{choose: func(_ int, sorted []string) []string { return keys(sorted) }}
		preKeyOrder = rec.order
		_ = preEditScanText(tool)
		preKeyOrder = nil
		if rec.err == nil {
			t.Errorf("recorder accepted a %s key", name)
		}
	}
}

// TestControlledOrderSameKeysDifferentObjectFails swaps the schedule entries of
// two maps that share a key set but differ in content. A key-set binding would
// accept the swap; the full fingerprint must not.
func TestControlledOrderSameKeysDifferentObjectFails(t *testing.T) {
	tool := mustTool(t, `{"name":"f","inputSchema":{"allOf":[{"p":"1","q":"2"},{"p":"3","q":"4"}]}}`)
	visits := recordSchedule(t, tool, func(ordinal int, sorted []string) []string {
		if ordinal == 1 {
			return []string{"q", "p"}
		}
		return sorted
	})
	if len(visits) != 3 || visits[1].fingerprint == visits[2].fingerprint {
		t.Fatalf("fixture shape changed: %+v", visits)
	}
	swapped := []scheduledVisit{
		visits[0],
		{ordinal: 1, fingerprint: visits[2].fingerprint, keys: visits[2].keys},
		{ordinal: 2, fingerprint: visits[1].fingerprint, keys: visits[1].keys},
	}
	if replayErr(tool, swapped) == nil {
		t.Fatal("swapped same-key objects were accepted")
	}
}

// randomSchema builds nested schemas with several text-bearing keys per
// object, which only a controlled schedule can compare.
func randomSchema(r *rand.Rand, depth int, n *int) any {
	*n++
	text := "t" + strconv.Itoa(*n)
	// The node budget keeps the generated tree linear in size; the depth
	// boundary has its own explicit fixture.
	if depth <= 0 || *n > 80 || r.IntN(6) == 0 {
		return []any{text, nil, 1.0, true, "", "object"}[r.IntN(6)]
	}
	if r.IntN(4) == 0 {
		items := make([]any, r.IntN(4))
		for i := range items {
			items[i] = randomSchema(r, depth-1, n)
		}
		return items
	}
	keys := []string{"description", "title", "default", "const", "pattern", "$comment", "x-v", "enum", "examples", "properties", "allOf", "items", "free", "type"}
	obj := map[string]any{}
	for range 1 + r.IntN(5) {
		obj[keys[r.IntN(len(keys))]] = randomSchema(r, depth-1, n)
	}
	return obj
}

func TestControlledOrderSeededCorpus(t *testing.T) {
	r := rand.New(rand.NewPCG(1835, 99)) //nolint:gosec // G404: deterministic test corpus, not security-sensitive
	for i := range 300 {
		var n int
		in, err := json.Marshal(randomSchema(r, 2+i%6, &n))
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(randomSchema(r, 3, &n))
		if err != nil {
			t.Fatal(err)
		}
		raw := fmt.Sprintf(`{"name":"tool_%d","description":"Describe %d","inputSchema":%s,"outputSchema":%s}`, i, i, in, out)
		tool := mustTool(t, raw)
		for seed := range uint64(64) {
			visits, text, spans := compareUnderSchedule(t, fmt.Sprintf("case %d seed %d", i, seed), tool, seededChooser(seed))
			checkSpanLayout(t, text, spans)
			if seed < 4 {
				checkSpanProvenance(t, raw, visits, spans)
			}
		}
	}
}

func TestControlledOrderDepthAndSizeBoundaries(t *testing.T) {
	deep := `"bottom"`
	for i := range maxSchemaDepth + 3 {
		deep = fmt.Sprintf(`{"a%d":%s,"b":"level %d"}`, i, deep, i)
	}
	wide := map[string]string{}
	for i := range 200 {
		wide["k"+strconv.Itoa(i)] = "v" + strconv.Itoa(i)
	}
	wideRaw, err := json.Marshal(wide)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"past the depth limit": `{"name":"f","inputSchema":` + deep + `}`,
		"two hundred keys":     `{"name":"f","inputSchema":{"properties":` + string(wideRaw) + `}}`,
	} {
		tool := mustTool(t, raw)
		for seed := range uint64(64) {
			_, text, spans := compareUnderSchedule(t, fmt.Sprintf("%s seed %d", name, seed), tool, seededChooser(seed))
			checkSpanLayout(t, text, spans)
		}
	}
}

// checkSpanLayout requires spans in order, inside the text, joined by exactly
// the ". " separator, covering the text end to end, with only the trailing
// general text lacking a pointer.
func checkSpanLayout(t *testing.T, text string, spans []toolTextSpan) {
	t.Helper()
	if text == "" {
		if len(spans) != 0 {
			t.Fatalf("spans %v over empty text", spans)
		}
		return
	}
	if len(spans) == 0 || spans[0].Start != 0 || spans[len(spans)-1].End != len(text) {
		t.Fatalf("spans %v do not cover %q end to end", spans, text)
	}
	for i, sp := range spans {
		if sp.End <= sp.Start || sp.End > len(text) {
			t.Fatalf("span %d %+v invalid for length %d", i, sp, len(text))
		}
		if i > 0 && text[spans[i-1].End:sp.Start] != ". " {
			t.Fatalf("separator before span %d is %q", i, text[spans[i-1].End:sp.Start])
		}
		if sp.Pointer == "" && i != len(spans)-1 {
			t.Fatalf("pointer-less span %d is not the trailing general text", i)
		}
	}
}

// checkSpanProvenance proves each pointer names the field that produced its
// span, independently of the walker. It rewrites only that field to a unique
// marker. The edit changes the fingerprints of the objects that contain the
// field, so the schedule is deliberately adapted: the oracle walk of the
// edited tool is re-recorded taking, at every ordinal, the original visit's
// key order, which must still be an exact permutation of the edited object's
// keys. The adapted schedule is then held to the full differential (oracle
// bytes equal new bytes) and the marker must appear once, exactly in that
// span, with every span's pointer unchanged. Equal strings in other fields
// cannot satisfy this for a wrong pointer.
func checkSpanProvenance(t *testing.T, raw string, visits []scheduledVisit, spans []toolTextSpan) {
	t.Helper()
	for i, sp := range spans {
		if sp.Pointer == "" {
			continue
		}
		marker := fmt.Sprintf("MARK%dKRAM", i)
		var doc any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		setPointer(t, doc, sp.Pointer, marker)
		edited, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		adapt := func(ordinal int, sorted []string) []string {
			if ordinal >= len(visits) {
				t.Fatalf("%s: edited walk made visit %d beyond the original %d", sp.Pointer, ordinal, len(visits))
			}
			return visits[ordinal].keys
		}
		label := "provenance " + sp.Pointer
		adapted, text, got := compareUnderSchedule(t, label, mustTool(t, string(edited)), adapt)
		if len(adapted) != len(visits) {
			t.Fatalf("%s: edited walk made %d visits, original %d", label, len(adapted), len(visits))
		}
		if strings.Count(text, marker) != 1 {
			t.Fatalf("%s: marker appears %d times", label, strings.Count(text, marker))
		}
		if len(got) != len(spans) || text[got[i].Start:got[i].End] != marker {
			t.Fatalf("%s: marker is not span %d of the replayed text", label, i)
		}
		for j := range spans {
			if got[j].Pointer != spans[j].Pointer {
				t.Fatalf("%s: span %d pointer moved from %s to %s", label, j, spans[j].Pointer, got[j].Pointer)
			}
		}
	}
}

func spanPointers(spans []toolTextSpan) []string {
	var out []string
	for _, sp := range spans {
		if sp.Pointer != "" {
			out = append(out, sp.Pointer)
		}
	}
	slices.Sort(out)
	return out
}

func setPointer(t *testing.T, doc any, ptr, value string) {
	t.Helper()
	tokens := strings.Split(ptr[1:], "/")
	for i, tok := range tokens {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		last := i == len(tokens)-1
		switch node := doc.(type) {
		case map[string]any:
			if _, ok := node[tok]; !ok {
				t.Fatalf("pointer %s: no member %q", ptr, tok)
			}
			if last {
				node[tok] = value
				return
			}
			doc = node[tok]
		case []any:
			idx, err := strconv.Atoi(tok)
			if err != nil || idx < 0 || idx >= len(node) {
				t.Fatalf("pointer %s: bad index %q", ptr, tok)
			}
			if last {
				node[idx] = value
				return
			}
			doc = node[idx]
		default:
			t.Fatalf("pointer %s descends into %T", ptr, doc)
		}
	}
}
