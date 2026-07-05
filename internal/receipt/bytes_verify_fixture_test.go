// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	creceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

type exactBytesCorpus struct {
	Valid     []exactBytesFixture  `json:"valid"`
	Mutations []exactBytesMutation `json:"mutations"`
}

type exactBytesFixture struct {
	ID           string `json:"id"`
	API          string `json:"api"`
	PublicKeyHex string `json:"public_key_hex"`
	SignerKeyID  string `json:"signer_key_id"`
	RawBase64    string `json:"raw_base64"`
}

type exactBytesMutation struct {
	ID       string                 `json:"id"`
	Source   string                 `json:"source"`
	Expect   string                 `json:"expect"`
	Mutation exactBytesMutationSpec `json:"mutation"`
	RawUTF8  string                 `json:"raw_utf8"`
}

type exactBytesMutationSpec struct {
	Kind string `json:"kind"`
	Old  string `json:"old"`
	New  string `json:"new"`
	Text string `json:"text"`
}

func TestEV1ExactBytesFixtureValidReceipts(t *testing.T) {
	t.Parallel()

	corpus := loadExactBytesCorpus(t)
	if len(corpus.Valid) == 0 {
		t.Fatal("fixture corpus has no valid receipts")
	}

	for _, fixture := range corpus.Valid {
		t.Run(fixture.ID, func(t *testing.T) {
			t.Parallel()
			if err := verifyExactBytesFixture(fixture, fixtureRaw(t, fixture)); err != nil {
				t.Fatalf("%s fixture: %v", fixture.API, err)
			}
		})
	}
}

func TestEV1ExactBytesFixtureMutationsReject(t *testing.T) {
	t.Parallel()

	corpus := loadExactBytesCorpus(t)
	for _, mutation := range corpus.Mutations {
		if mutation.Expect != "reject" {
			t.Fatalf("mutation %q has unsupported expectation %q", mutation.ID, mutation.Expect)
		}
		for _, fixture := range fixturesForMutation(t, corpus.Valid, mutation.Source) {
			t.Run(mutation.ID+"/"+fixture.ID, func(t *testing.T) {
				t.Parallel()
				raw := mutation.RawUTF8
				mutated := []byte(raw)
				if mutation.Source != "none" {
					var err error
					mutated, err = applyExactBytesMutation(fixtureRaw(t, fixture), mutation.Mutation)
					if err != nil {
						t.Fatalf("apply mutation: %v", err)
					}
				}
				if err := verifyExactBytesFixture(fixture, mutated); err == nil {
					t.Fatalf("%s accepted mutation %q: %s", fixture.API, mutation.ID, mutated)
				}
			})
		}
	}
}

func TestEV1ExactBytesCrossAPIVersionConfusionRejects(t *testing.T) {
	t.Parallel()

	corpus := loadExactBytesCorpus(t)
	v1 := exactBytesFixtureByID(t, corpus.Valid, "v1-action-receipt")
	v2 := exactBytesFixtureByID(t, corpus.Valid, "v2-evidence-receipt")

	if err := creceipt.VerifyV2BytesWithKey(fixtureRaw(t, v1), fixturePublicKey(t, v1), v1.SignerKeyID); err == nil {
		t.Fatal("VerifyV2BytesWithKey accepted v1 receipt bytes")
	}
	if err := VerifyV1BytesWithKey(fixtureRaw(t, v2), v2.PublicKeyHex); err == nil {
		t.Fatal("VerifyV1BytesWithKey accepted v2 receipt bytes")
	}
}

func TestEV1ExactBytesHostileEnvelopeSpellingsReject(t *testing.T) {
	t.Parallel()

	corpus := loadExactBytesCorpus(t)
	cases := []struct {
		name       string
		source     string
		mutate     func([]byte) []byte
		wantErrSub string
	}{
		{
			name:       "v1 byte order mark",
			source:     "v1-action-receipt",
			wantErrSub: "strict decode",
			mutate: func(raw []byte) []byte {
				return append([]byte{0xef, 0xbb, 0xbf}, raw...)
			},
		},
		{
			name:       "v2 byte order mark",
			source:     "v2-evidence-receipt",
			wantErrSub: "strict decode",
			mutate: func(raw []byte) []byte {
				return append([]byte{0xef, 0xbb, 0xbf}, raw...)
			},
		},
		{
			name:       "v1 escaped duplicate top level key",
			source:     "v1-action-receipt",
			wantErrSub: "duplicate object key",
			mutate: func(raw []byte) []byte {
				return insertAfterObjectStart(raw, []byte(`"\u0076ersion":1,`))
			},
		},
		{
			name:       "v2 escaped duplicate top level key",
			source:     "v2-evidence-receipt",
			wantErrSub: "duplicate object key",
			mutate: func(raw []byte) []byte {
				return insertAfterObjectStart(raw, []byte(`"\u0072ecord_type":"evidence_receipt_v2",`))
			},
		},
		{
			name:       "v1 surrogate pair duplicate key",
			source:     "v1-action-receipt",
			wantErrSub: "duplicate object key",
			mutate: func(raw []byte) []byte {
				return insertAfterObjectStart(raw, []byte(`"\uD834\uDD1E":1,"\ud834\udd1e":2,`))
			},
		},
		{
			name:       "v2 surrogate pair duplicate key",
			source:     "v2-evidence-receipt",
			wantErrSub: "duplicate object key",
			mutate: func(raw []byte) []byte {
				return insertAfterObjectStart(raw, []byte(`"\uD834\uDD1E":1,"\ud834\udd1e":2,`))
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := exactBytesFixtureByID(t, corpus.Valid, tc.source)
			if err := verifyExactBytesFixture(fixture, tc.mutate(fixtureRaw(t, fixture))); err == nil {
				t.Fatalf("%s accepted hostile envelope spelling", fixture.API)
			} else if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("%s error = %q, want substring %q", fixture.API, err, tc.wantErrSub)
			}
		})
	}
}

func loadExactBytesCorpus(t *testing.T) exactBytesCorpus {
	t.Helper()
	raw, err := os.ReadFile("../testdata/ev1_exact_bytes/receipt_mutation_corpus.json")
	if err != nil {
		t.Fatalf("Read fixture corpus: %v", err)
	}
	var corpus exactBytesCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("Unmarshal fixture corpus: %v", err)
	}
	return corpus
}

func fixtureRaw(t *testing.T, fixture exactBytesFixture) []byte {
	t.Helper()
	receiptBytes, err := base64.StdEncoding.DecodeString(fixture.RawBase64)
	if err != nil {
		t.Fatalf("Decode raw_base64 for %s: %v", fixture.ID, err)
	}
	return receiptBytes
}

func fixturePublicKey(t *testing.T, fixture exactBytesFixture) ed25519.PublicKey {
	t.Helper()
	pub, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode public_key_hex for %s: %v", fixture.ID, err)
	}
	return ed25519.PublicKey(pub)
}

func verifyExactBytesFixture(fixture exactBytesFixture, receiptBytes []byte) error {
	pub, err := hex.DecodeString(fixture.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("decode public_key_hex: %w", err)
	}
	switch fixture.API {
	case "VerifyV1BytesWithKey":
		return VerifyV1BytesWithKey(receiptBytes, fixture.PublicKeyHex)
	case "VerifyV2BytesWithKey":
		return creceipt.VerifyV2BytesWithKey(receiptBytes, ed25519.PublicKey(pub), fixture.SignerKeyID)
	default:
		return fmt.Errorf("unknown fixture API %q", fixture.API)
	}
}

func exactBytesFixtureByID(t *testing.T, fixtures []exactBytesFixture, id string) exactBytesFixture {
	t.Helper()
	for _, fixture := range fixtures {
		if fixture.ID == id {
			return fixture
		}
	}
	t.Fatalf("fixture %q not found", id)
	return exactBytesFixture{}
}

func fixturesForMutation(t *testing.T, fixtures []exactBytesFixture, source string) []exactBytesFixture {
	t.Helper()
	if source == "both" || source == "none" {
		return fixtures
	}
	for _, fixture := range fixtures {
		if fixture.ID == source {
			return []exactBytesFixture{fixture}
		}
	}
	t.Fatalf("mutation source %q did not match any valid fixture", source)
	return nil
}

func insertAfterObjectStart(raw, text []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	out := []byte{'{'}
	out = append(out, text...)
	out = append(out, trimmed[1:]...)
	return out
}

func applyExactBytesMutation(raw []byte, spec exactBytesMutationSpec) ([]byte, error) {
	switch spec.Kind {
	case "replace_once":
		old := []byte(spec.Old)
		idx := bytes.Index(raw, old)
		if idx < 0 {
			return nil, fmt.Errorf("old text %q not found", spec.Old)
		}
		out := append([]byte(nil), raw[:idx]...)
		out = append(out, spec.New...)
		out = append(out, raw[idx+len(old):]...)
		return out, nil
	case "insert_after_object_start":
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("input is not an object")
		}
		out := []byte{'{'}
		out = append(out, spec.Text...)
		out = append(out, trimmed[1:]...)
		return out, nil
	case "append":
		out := append([]byte(nil), raw...)
		out = append(out, spec.Text...)
		return out, nil
	case "drop_last_byte":
		if len(raw) == 0 {
			return nil, fmt.Errorf("cannot drop byte from empty input")
		}
		return append([]byte(nil), raw[:len(raw)-1]...), nil
	case "move_first_top_level_key_after_second":
		fields, err := topLevelObjectFields(raw)
		if err != nil {
			return nil, err
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("need at least two top-level fields")
		}
		reordered := append([]string{fields[1], fields[0]}, fields[2:]...)
		return joinTopLevelObjectFields(reordered), nil
	case "duplicate_first_top_level_key":
		fields, err := topLevelObjectFields(raw)
		if err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return nil, fmt.Errorf("need at least one top-level field")
		}
		duplicated := append([]string{fields[0]}, fields...)
		return joinTopLevelObjectFields(duplicated), nil
	default:
		return nil, fmt.Errorf("unsupported mutation kind %q", spec.Kind)
	}
}

func topLevelObjectFields(raw []byte) ([]string, error) {
	trimmed := string(bytes.TrimSpace(raw))
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return nil, fmt.Errorf("input is not a JSON object")
	}
	body := trimmed[1 : len(trimmed)-1]
	if body == "" {
		return nil, nil
	}
	fields := make([]string, 0)
	start := 0
	depth := 0
	inString := false
	escaped := false
	for i, r := range body {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch r {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced JSON object")
			}
		case ',':
			if depth == 0 {
				fields = append(fields, body[start:i])
				start = i + 1
			}
		}
	}
	if inString || depth != 0 {
		return nil, fmt.Errorf("unterminated JSON object")
	}
	fields = append(fields, body[start:])
	return fields, nil
}

func joinTopLevelObjectFields(fields []string) []byte {
	return []byte("{" + strings.Join(fields, ",") + "}")
}
