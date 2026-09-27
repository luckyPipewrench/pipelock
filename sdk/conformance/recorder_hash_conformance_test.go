// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The recorder writes every evidence entry into an unkeyed hash chain:
// hash = sha256 over a NUL-separated projection of the entry, and each entry's
// prev_hash names the hash before it. The TypeScript and Rust verifiers port
// that check (Go finding outer_chain_broken). These vectors record what Go's
// recorder.ComputeHash and recorder.VerifyChain actually return for recorder
// lines, including the parser edges that shape the hash input: timestamps with
// offsets and long fractions, a missing or null detail, detail bytes kept
// verbatim, and v1, v2 and v3 projections. Regenerate with
// PIPELOCK_RECORDER_HASH_FIXTURES=1.
const recorderHashFile = "testdata/recorder-hash/vectors.json"

// Placeholders in the line templates. hashHole is replaced by the computed
// hash, which is not part of the hash input; prevHole by the previous
// entry's hash in a chain.
const (
	hashHole = "__HASH__"
	prevHole = "__PREV__"
)

type recorderHashVector struct {
	Name string `json:"name"`
	Line string `json:"line"`
	Hash string `json:"hash"`
}

type recorderRejectVector struct {
	Name  string `json:"name"`
	Line  string `json:"line"`
	Error string `json:"error"`
}

type recorderChainVector struct {
	Name  string   `json:"name"`
	Lines []string `json:"lines"`
	// Error is recorder.VerifyChain's error, or empty when the chain holds.
	Error string `json:"error"`
}

type recorderHashFixture struct {
	Description string                 `json:"description"`
	Hashes      []recorderHashVector   `json:"hashes"`
	Rejects     []recorderRejectVector `json:"rejects"`
	Chains      []recorderChainVector  `json:"chains"`
}

const v2Detail = `{"b":1,"a":"x"}`

// recorderHashTemplates are single entries whose hash is computed by Go.
var recorderHashTemplates = []struct{ name, line string }{
	{"v1 minimal", `{"v":1,"seq":0,"ts":"2026-09-27T18:36:18.011030409Z","session_id":"s","type":"decision","transport":"t","summary":"x","detail":null,"prev_hash":"genesis","hash":"__HASH__"}`},
	{"v1 ignores event_kind", `{"v":1,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","event_kind":"read","transport":"t","summary":"x","detail":{},"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 full", `{"v":2,"seq":7,"ts":"2026-09-27T18:36:18.5Z","session_id":"proxy.run.0123","trace_id":"tr","type":"action_receipt","event_kind":"read","transport":"receipt_session","summary":"receipt: allow","detail":` + v2Detail + `,"raw_ref":"ref","prev_hash":"p","hash":"__HASH__"}`},
	{"v2 detail absent", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","prev_hash":"p","hash":"__HASH__"}`},
	{"v2 detail whitespace and escapes kept verbatim", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail": { "z" : [1, 2.50, 1e3] , "a":"<\/é" } ,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 fraction trailing zeros trimmed", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18.120000000Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 fraction of zeros dropped", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18.000Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 fraction beyond nanoseconds truncated", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18.1234567899Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 positive offset converted to UTC", `{"v":2,"seq":1,"ts":"2026-09-28T00:06:18.25+05:30","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 negative offset crossing midnight and year", `{"v":2,"seq":1,"ts":"2026-12-31T22:00:00-04:00","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 leap day", `{"v":2,"seq":1,"ts":"2028-02-29T23:59:59.999999999Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 null ts is the zero time", `{"v":2,"seq":1,"ts":null,"session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 missing ts is the zero time", `{"v":2,"seq":1,"session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 null strings are empty", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":null,"trace_id":null,"type":"decision","event_kind":null,"transport":"t","summary":null,"detail":1,"raw_ref":null,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 seq beyond 2^53", `{"v":2,"seq":18446744073709551615,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 unicode and escaped strings", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"sé","type":"decision","transport":"t","summary":"a<b>& \"\\ 😀 é","detail":1,"prev_hash":"p","hash":"__HASH__"}`},
	{"v2 unknown top-level field ignored", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"extra":{"q":1},"prev_hash":"p","hash":"__HASH__"}`},
	{"v3 namespace fields", `{"v":3,"seq":2,"ts":"2026-09-27T18:36:18.011Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"w1","type":"decision","event_kind":"k","transport":"t","summary":"x","detail":{"a":1},"prev_hash":"p","hash":"__HASH__"}`},
}

// recorderRejectTemplates are entries Go refuses to read or hash.
var recorderRejectTemplates = []struct{ name, line string }{
	{"ts escaped zone refused", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18\u005a","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"NUL in summary", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a\u0000b","detail":1,"prev_hash":"p","hash":"h"}`},
	{"legacy entry with namespace", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","chain_kind":"recorder","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"ts hour out of range", `{"v":2,"seq":1,"ts":"2026-09-27T24:00:00Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"ts day out of range", `{"v":2,"seq":1,"ts":"2026-02-30T00:00:00Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"ts without zone", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"ts lowercase separator", `{"v":2,"seq":1,"ts":"2026-09-27t18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"seq negative", `{"v":2,"seq":-1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"seq fraction", `{"v":2,"seq":1.5,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"","detail":1,"prev_hash":"p","hash":"h"}`},
	{"summary not a string", `{"v":2,"seq":1,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":5,"detail":1,"prev_hash":"p","hash":"h"}`},
}

// recorderChainTemplates are whole chains checked with recorder.VerifyChain.
var recorderChainTemplates = []struct {
	name  string
	lines []string
}{
	{"valid v2 chain", []string{
		`{"v":2,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":2,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"__PREV__","hash":"__HASH__"}`,
		`{"v":2,"seq":2,"ts":"2026-09-27T18:36:20Z","session_id":"s","type":"decision","transport":"t","summary":"c","detail":3,"prev_hash":"__PREV__","hash":"__HASH__"}`,
	}},
	{"valid v1 then v2", []string{
		`{"v":1,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":2,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"__PREV__","hash":"__HASH__"}`,
	}},
	{"first entry not genesis", []string{
		`{"v":2,"seq":3,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"0000","hash":"__HASH__"}`,
	}},
	{"prev_hash break", []string{
		`{"v":2,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":2,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"ffff","hash":"__HASH__"}`,
	}},
	{"stored hash edited", []string{
		`{"v":2,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"0000000000000000000000000000000000000000000000000000000000000000"}`,
	}},
	{"v3 namespace changed", []string{
		`{"v":3,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"w1","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":3,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"w2","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"__PREV__","hash":"__HASH__"}`,
	}},
	{"v3 after legacy", []string{
		`{"v":2,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":3,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"w1","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"__PREV__","hash":"__HASH__"}`,
	}},
	{"legacy after v3", []string{
		`{"v":3,"seq":0,"ts":"2026-09-27T18:36:18Z","session_id":"s","chain_kind":"recorder","writer_instance_id":"w1","type":"decision","transport":"t","summary":"a","detail":1,"prev_hash":"genesis","hash":"__HASH__"}`,
		`{"v":2,"seq":1,"ts":"2026-09-27T18:36:19Z","session_id":"s","type":"decision","transport":"t","summary":"b","detail":2,"prev_hash":"__PREV__","hash":"__HASH__"}`,
	}},
}

// sealLine parses a template line and fills in its hash.
func sealLine(t *testing.T, line string) (string, string) {
	t.Helper()
	e, err := recorder.ParseEntryLine([]byte(line))
	if err != nil {
		t.Fatalf("parse %s: %v", line, err)
	}
	h := recorder.ComputeHash(e)
	if h == "" {
		t.Fatalf("no hash for %s", line)
	}
	return strings.Replace(line, hashHole, h, 1), h
}

func buildRecorderHashFixture(t *testing.T) []byte {
	t.Helper()
	fx := recorderHashFixture{
		Description: "recorder.ComputeHash for each line, recorder.ParseEntryLine rejections, and recorder.VerifyChain over whole chains, all from Go",
		Rejects:     []recorderRejectVector{},
	}
	for _, v := range recorderHashTemplates {
		line, h := sealLine(t, v.line)
		fx.Hashes = append(fx.Hashes, recorderHashVector{Name: v.name, Line: line, Hash: h})
	}
	for _, v := range recorderRejectTemplates {
		_, err := recorder.ParseEntryLine([]byte(v.line))
		if err == nil {
			var e recorder.Entry
			e, err = recorder.ParseEntryLine([]byte(v.line))
			if err == nil {
				err = recorder.ValidateEntrySchema(e)
			}
		}
		if err == nil {
			t.Fatalf("reject vector %q was accepted by Go", v.name)
		}
		fx.Rejects = append(fx.Rejects, recorderRejectVector{Name: v.name, Line: v.line, Error: err.Error()})
	}
	for _, c := range recorderChainTemplates {
		var (
			lines   []string
			entries []recorder.Entry
			prev    string
		)
		for _, tmpl := range c.lines {
			line := strings.Replace(tmpl, prevHole, prev, 1)
			if strings.Contains(line, hashHole) {
				line, prev = sealLine(t, line)
			}
			e, err := recorder.ParseEntryLine([]byte(line))
			if err != nil {
				t.Fatalf("chain %q: %v", c.name, err)
			}
			if !strings.Contains(tmpl, hashHole) {
				prev = e.Hash
			}
			lines = append(lines, line)
			entries = append(entries, e)
		}
		cv := recorderChainVector{Name: c.name, Lines: lines}
		if err := recorder.VerifyChain(entries); err != nil {
			cv.Error = err.Error()
		}
		fx.Chains = append(fx.Chains, cv)
	}
	out, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// TestRecorderHashFixtureMatchesGo fails when the committed vectors no longer
// state what Go's recorder computes.
func TestRecorderHashFixtureMatchesGo(t *testing.T) {
	got := buildRecorderHashFixture(t)
	if os.Getenv("PIPELOCK_RECORDER_HASH_FIXTURES") == "1" {
		if err := os.MkdirAll(filepath.Dir(recorderHashFile), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recorderHashFile, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(recorderHashFile)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with PIPELOCK_RECORDER_HASH_FIXTURES=1)", recorderHashFile, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s is stale; regenerate with PIPELOCK_RECORDER_HASH_FIXTURES=1", recorderHashFile)
	}
}

// TestRecorderHashFixtureCoversBothVerdicts keeps the chain vectors meaningful.
func TestRecorderHashFixtureCoversBothVerdicts(t *testing.T) {
	var fx recorderHashFixture
	if err := json.Unmarshal(buildRecorderHashFixture(t), &fx); err != nil {
		t.Fatal(err)
	}
	var valid, broken int
	for _, c := range fx.Chains {
		if c.Error == "" {
			valid++
		} else {
			broken++
		}
	}
	if valid < 2 || broken < 4 {
		t.Fatalf("want at least 2 valid and 4 broken chains, got %d and %d", valid, broken)
	}
}
