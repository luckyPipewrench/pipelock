// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	anchorBundleExamplePath = "../../sdk/anchor-bundle/example.json"
	anchorBundleSchemaPath  = "../../sdk/anchor-bundle/v1.json"
)

func TestAnchorBundleV1Golden(t *testing.T) {
	path := filepath.Clean(anchorBundleExamplePath)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden anchor bundle: %v", err)
	}

	loaded, err := LoadBundleBytes(original)
	if err != nil {
		t.Fatalf("strict-load golden anchor bundle: %v", err)
	}
	want := goldenAnchorBundleV1()
	if !reflect.DeepEqual(loaded, want) {
		t.Fatal("golden anchor bundle drifted from the pinned v1 fixture values")
	}

	roundTrip, err := bundleBytes(loaded)
	if err != nil {
		t.Fatalf("marshal golden anchor bundle: %v", err)
	}
	if !bytes.Equal(roundTrip, original) {
		t.Fatalf("golden anchor bundle did not byte-for-byte round-trip\nround-trip:\n%s\noriginal:\n%s", roundTrip, original)
	}
}

func TestAnchorBundleV1SchemaTracksGoJSONFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(anchorBundleSchemaPath))
	if err != nil {
		t.Fatalf("read anchor bundle schema: %v", err)
	}
	var schema struct {
		ID         string                     `json:"$id"`
		Properties map[string]json.RawMessage `json:"properties"`
		Defs       map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse anchor bundle schema: %v", err)
	}
	if schema.ID != "https://pipelab.org/schemas/anchor-bundle-v1.schema.json" {
		t.Fatalf("anchor bundle schema $id = %q", schema.ID)
	}

	assertJSONFieldsMatchSchema(t, reflect.TypeFor[Bundle](), schema.Properties)
	assertJSONFieldsMatchSchema(t, reflect.TypeFor[Checkpoint](), schema.Defs["checkpoint"].Properties)
	assertJSONFieldsMatchSchema(t, reflect.TypeFor[Proof](), schema.Defs["proof"].Properties)
	assertJSONFieldsMatchSchema(t, reflect.TypeFor[RekorProof](), schema.Defs["rekor_proof"].Properties)
	assertJSONFieldsMatchSchema(t, reflect.TypeFor[RekorInclusionProof](), schema.Defs["rekor_inclusion_proof"].Properties)
}

func assertJSONFieldsMatchSchema(t *testing.T, typ reflect.Type, properties map[string]json.RawMessage) {
	t.Helper()
	got := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		name := typ.Field(i).Tag.Get("json")
		if comma := bytes.IndexByte([]byte(name), ','); comma >= 0 {
			name = name[:comma]
		}
		if name != "" && name != "-" {
			got = append(got, name)
		}
	}
	sort.Strings(got)

	want := make([]string, 0, len(properties))
	for name := range properties {
		want = append(want, name)
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s JSON fields = %v, schema properties = %v", typ.Name(), got, want)
	}
}

func TestAnchorBundleV1SchemaIntegerFieldsAreBounded(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(anchorBundleSchemaPath))
	if err != nil {
		t.Fatalf("read anchor bundle schema: %v", err)
	}
	var schema struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Maximum json.Number `json:"maximum"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse anchor bundle schema: %v", err)
	}
	// Every published integer field must carry the Go decode bound so a future
	// widening trips this guard instead of silently accepting values the runtime
	// rejects. JSON numbers stay exact here because json.Number keeps the literal.
	const (
		uint64Max = "18446744073709551615"
		int64Max  = "9223372036854775807"
	)
	for _, tc := range []struct{ def, field, max string }{
		{"checkpoint", "final_seq", uint64Max},
		{"checkpoint", "receipt_count", uint64Max},
		{"proof", "log_index", uint64Max},
		{"rekor_proof", "integrated_time", int64Max},
		{"rekor_inclusion_proof", "log_index", uint64Max},
		{"rekor_inclusion_proof", "tree_size", uint64Max},
	} {
		t.Run(tc.def+"."+tc.field, func(t *testing.T) {
			prop, ok := schema.Defs[tc.def].Properties[tc.field]
			if !ok {
				t.Fatalf("schema $defs.%s.%s is missing", tc.def, tc.field)
			}
			if got := prop.Maximum.String(); got != tc.max {
				t.Fatalf("schema $defs.%s.%s maximum = %q, want %q", tc.def, tc.field, got, tc.max)
			}
		})
	}
}

// TestAnchorBundleV1SchemaForbidsRekorOnNonRekorProof guards the proof
// conditional: rekor material is Rekor-specific, so a non-Rekor proof (e.g. the
// local backend) must not carry a rekor object. The spec states other backends
// do not gain the extension object, and the schema must express that.
func TestAnchorBundleV1SchemaForbidsRekorOnNonRekorProof(t *testing.T) {
	data, err := os.ReadFile(filepath.Clean(anchorBundleSchemaPath))
	if err != nil {
		t.Fatalf("read anchor bundle schema: %v", err)
	}
	var schema struct {
		Defs map[string]struct {
			AllOf []struct {
				Else struct {
					Not struct {
						Required []string `json:"required"`
					} `json:"not"`
				} `json:"else"`
			} `json:"allOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse anchor bundle schema: %v", err)
	}
	forbidden := false
	for _, cond := range schema.Defs["proof"].AllOf {
		for _, req := range cond.Else.Not.Required {
			if req == "rekor" {
				forbidden = true
			}
		}
	}
	if !forbidden {
		t.Fatal("proof schema must forbid the rekor property when backend is not rekor")
	}
}

// compileAnchorBundleV1Schema compiles the published schema as Draft 2020-12
// with format assertions enabled. jsonschema.UnmarshalJSON preserves numeric
// literals (json.Number / big.Rat), so integer bounds beyond float64's exact
// range are compared exactly instead of being collapsed to a float.
func compileAnchorBundleV1Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(filepath.Clean(anchorBundleSchemaPath))
	if err != nil {
		t.Fatalf("open anchor bundle schema: %v", err)
	}
	defer func() { _ = f.Close() }()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("parse anchor bundle schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat() // treat date-time / uri as assertions, not annotations
	if err := c.AddResource("anchor-bundle-v1.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("anchor-bundle-v1.json")
	if err != nil {
		t.Fatalf("compile anchor bundle schema: %v", err)
	}
	return sch
}

func validateAnchorBundleInstance(t *testing.T, sch *jsonschema.Schema, raw []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse instance: %v", err)
	}
	return sch.Validate(inst)
}

// TestAnchorBundleV1SchemaValidatesDocuments proves the published schema
// actually accepts the fixture and REJECTS violating documents, complementing
// the structural checks (which prove the constraints have not drifted).
func TestAnchorBundleV1SchemaValidatesDocuments(t *testing.T) {
	sch := compileAnchorBundleV1Schema(t)
	base, err := os.ReadFile(filepath.Clean(anchorBundleExamplePath))
	if err != nil {
		t.Fatalf("read anchor bundle fixture: %v", err)
	}
	if err := validateAnchorBundleInstance(t, sch, base); err != nil {
		t.Fatalf("published fixture must validate against v1 schema: %v", err)
	}

	baseStr := string(base)
	for _, tc := range []struct {
		name   string
		mutate func(string) string
	}{
		{
			// 2^64 exceeds float64's exact-integer range; a precision-losing
			// validator would accept it. This is the case AJV cannot catch.
			name: "reject_final_seq_above_uint64_max",
			mutate: func(s string) string {
				return strings.Replace(s, `"final_seq": 41`, `"final_seq": 18446744073709551616`, 1)
			},
		},
		{
			name:   "reject_rekor_material_on_local_proof",
			mutate: func(s string) string { return strings.ReplaceAll(s, `"backend": "rekor"`, `"backend": "local"`) },
		},
		{
			name: "reject_malformed_created_at",
			mutate: func(s string) string {
				return strings.Replace(s, `"created_at": "2026-07-23T16:30:00Z"`, `"created_at": "not-a-timestamp"`, 1)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(baseStr)
			if mutated == baseStr {
				t.Fatalf("mutation produced no change; fixture substring drifted for %q", tc.name)
			}
			if err := validateAnchorBundleInstance(t, sch, []byte(mutated)); err == nil {
				t.Fatalf("schema must reject a document that %s", strings.ReplaceAll(tc.name, "_", " "))
			}
		})
	}
}

func goldenAnchorBundleV1() Bundle {
	return Bundle{
		Version:   BundleVersion,
		Backend:   RekorBackend,
		CreatedAt: time.Date(2026, 7, 23, 16, 30, 0, 0, time.UTC),
		Checkpoint: Checkpoint{
			SessionID:    "agent-a",
			FinalSeq:     41,
			RootHash:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ReceiptCount: 42,
			StartTime:    time.Date(2026, 7, 23, 16, 0, 0, 0, time.UTC),
			EndTime:      time.Date(2026, 7, 23, 16, 29, 30, 0, time.UTC),
			SignerKeys: []string{
				"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			},
		},
		Proof: Proof{
			Backend:     RekorBackend,
			LogID:       "example-log-id",
			LogIndex:    7,
			EntryHash:   "1111111111111111111111111111111111111111111111111111111111111111",
			LogRootHash: "2222222222222222222222222222222222222222222222222222222222222222",
			Rekor: &RekorProof{
				URL:                  "https://rekor.vendor.example",
				UUID:                 "example-entry-uuid",
				Body:                 "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIn0=",
				PublicKey:            "-----BEGIN PUBLIC KEY-----\nZXhhbXBsZQ==\n-----END PUBLIC KEY-----\n",
				Signature:            "ZXhhbXBsZS1zaWduYXR1cmU=",
				IntegratedTime:       1784824200,
				SignedEntryTimestamp: "ZXhhbXBsZS1zZXQ=",
				InclusionProof: &RekorInclusionProof{
					RootHash: "2222222222222222222222222222222222222222222222222222222222222222",
					LogIndex: 7,
					TreeSize: 8,
					Hashes: []string{
						"3333333333333333333333333333333333333333333333333333333333333333",
					},
					Checkpoint: "example-log.example - 8\nexample-checkpoint-signature\n",
				},
			},
		},
		Limits: []string{
			"Rekor verification proves the checkpoint entry has a valid SET and inclusion proof under a pinned Rekor log key.",
			"Rekor anchoring does not prove the checkpoint was witnessed before every later action unless the anchored checkpoint covers the whole receipt chain being verified.",
			"Rekor anchoring does not prove the log remained globally consistent after the recorded checkpoint without a later consistency audit.",
			"Anchoring does not prove real-time truth by whoever held the receipt signing key.",
		},
	}
}
