// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func secretEgressWireFixture(t *testing.T) ([]byte, receipt.EvidenceReceipt) {
	t.Helper()
	r, _ := signedSecretEgressReceipt(t, "intent-block")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw, r
}

func editSecretEgressWire(t *testing.T, raw []byte, edit func(map[string]json.RawMessage)) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	edit(fields)
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSecretEgressWireRequiredExactFields(t *testing.T) {
	t.Parallel()
	raw, _ := secretEgressWireFixture(t)
	required := []string{"record_type", "receipt_version", "payload_kind", "canonicalization", "crit", "event_id", "timestamp", "signature", "chain_seq", "chain_prev_hash", "policy_hash", "payload"}
	for _, key := range required {
		for _, operation := range []string{"omit", "null", "case-alias"} {
			t.Run(key+"/"+operation, func(t *testing.T) {
				invalid := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) {
					switch operation {
					case "omit":
						delete(fields, key)
					case "null":
						fields[key] = json.RawMessage(`null`)
					case "case-alias":
						fields[strings.ToUpper(key)] = fields[key]
						delete(fields, key)
					}
				})
				if _, err := receipt.ParseEvidenceReceipt(invalid); err == nil {
					t.Fatal("strict binding accepted invalid new-kind wire fields")
				}
			})
		}
	}
	invalid := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) { fields["unknown"] = json.RawMessage(`true`) })
	if _, err := receipt.ParseEvidenceReceipt(invalid); err == nil {
		t.Fatal("strict binding accepted unknown new-kind field")
	}
	duplicate := bytes.Replace(raw, []byte(`"payload_kind":`), []byte(`"payload_kind":"secret_egress_decision_v1","payload_kind":`), 1)
	if _, err := receipt.ParseEvidenceReceipt(duplicate); err == nil {
		t.Fatal("strict binding accepted duplicate new-kind selector")
	}
}

func TestSecretEgressWireOptionalFieldsAndIntegerSpelling(t *testing.T) {
	t.Parallel()
	raw, _ := secretEgressWireFixture(t)
	cases := []struct {
		field   string
		valid   []string
		invalid []string
	}{
		{"principal", []string{`"fixture-principal"`}, []string{`null`, `""`, `42`, `true`, `[]`, `{}`}},
		{"actor", []string{`"fixture-actor"`}, []string{`null`, `""`, `42`, `true`, `[]`, `{}`}},
		{"active_manifest_hash", []string{`"reference"`}, []string{`null`, `""`, `42`, `true`, `[]`, `{}`}},
		{"contract_hash", []string{`"reference"`}, []string{`null`, `""`, `42`, `true`, `[]`, `{}`}},
		{"selector_id", []string{`"selector"`}, []string{`null`, `""`, `42`, `true`, `[]`, `{}`}},
		{"delegation_chain", []string{`["principal-a","principal-b"]`}, []string{`null`, `[]`, `[""]`, `[null]`, `[42]`, `[true]`, `"principal"`, `{}`}},
		{"contract_generation", []string{`1`, `9007199254740991`}, []string{`null`, `0`, `-0`, `1.0`, `1e0`, `9007199254740992`, `18446744073709551616`, `-1`, `true`, `"1"`, `[]`, `{}`}},
		{"chain_seq", []string{`0`, `1`, `9007199254740991`}, []string{`null`, `-0`, `0.0`, `0e0`, `9007199254740992`, `18446744073709551616`, `-1`, `true`, `"0"`, `[]`, `{}`}},
		{"receipt_version", []string{`2`}, []string{`null`, `2.0`, `2e0`, `true`, `"2"`, `[]`, `{}`}},
	}
	for _, c := range cases {
		for _, group := range []struct {
			values []string
			valid  bool
		}{{c.valid, true}, {c.invalid, false}} {
			for _, value := range group.values {
				t.Run(c.field+"/"+value, func(t *testing.T) {
					changed := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) { fields[c.field] = json.RawMessage(value) })
					if _, err := receipt.ParseEvidenceReceipt(changed); (err == nil) != group.valid {
						t.Fatalf("valid=%v, decode error=%v", group.valid, err)
					}
				})
			}
		}
	}
}

func TestSecretEgressWireNestedEnvelopeObjects(t *testing.T) {
	t.Parallel()
	raw, _ := secretEgressWireFixture(t)
	for _, field := range []string{"signature", "canonicalization"} {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(envelope[field], &object); err != nil {
			t.Fatal(err)
		}
		for key := range object {
			for _, operation := range []string{"omit", "null", "numeric", "case-alias"} {
				t.Run(field+"/"+key+"/"+operation, func(t *testing.T) {
					changed := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) {
						fields[field] = editSecretEgressWire(t, fields[field], func(nested map[string]json.RawMessage) {
							switch operation {
							case "omit":
								delete(nested, key)
							case "null":
								nested[key] = json.RawMessage(`null`)
							case "numeric":
								nested[key] = json.RawMessage(`1`)
							case "case-alias":
								nested[strings.ToUpper(key)] = nested[key]
								delete(nested, key)
							}
						})
					})
					if _, err := receipt.ParseEvidenceReceipt(changed); err == nil {
						t.Fatal("accepted malformed nested envelope object")
					}
				})
			}
		}
	}
}

func TestSecretEgressWireCanonicalUTCTimestamp(t *testing.T) {
	t.Parallel()
	raw, _ := secretEgressWireFixture(t)
	cases := []struct {
		value string
		valid bool
	}{
		{"2026-09-30T12:00:00Z", true},
		{"2026-09-30T12:00:00.1Z", true},
		{"2026-09-30T12:00:00.123456789Z", true},
		{"0000-02-29T00:00:00Z", true},
		{"2024-02-29T00:00:00Z", true},
		{"\\u0032026-09-30T12:00:00Z", false},
		{"2026-09-30T12:00:00\\u005a", false},
		{"0001-01-01T00:00:00Z", false},
		{"2026-09-30T12:00:00+00:00", false},
		{"2026-09-30T12:00:00-05:00", false},
		{"2026-09-30T12:00:00.100Z", false},
		{"2026-09-30T12:00:00.000Z", false},
		{"2026-09-30T12:00:00.1234567891Z", false},
		{"2026-09-30T1:00:00Z", false},
		{"2026-09-30T12:00:00,1Z", false},
		{"2026-02-29T00:00:00Z", false},
		{"2026-09-30T24:00:00Z", false},
		{"2026-09-30T00:60:00Z", false},
		{"2026-09-30T00:00:60Z", false},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			changed := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) { fields["timestamp"] = json.RawMessage(`"` + c.value + `"`) })
			if _, err := receipt.ParseEvidenceReceipt(changed); (err == nil) != c.valid {
				t.Fatalf("valid=%v, decode=%v", c.valid, err)
			}
		})
	}
}

func TestSecretEgressWireReadEntryPointsRejectBeforeBinding(t *testing.T) {
	t.Parallel()
	raw, r := secretEgressWireFixture(t)
	pub := secretEgressWirePublicKey(t, r.Signature.SignerKeyID)
	if err := receipt.VerifyV2BytesWithKey(raw, pub, r.Signature.SignerKeyID); err != nil {
		t.Fatalf("baseline exact-byte receipt: %v", err)
	}
	baselineStream, err := receipt.NewPinnedStreamingVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := baselineStream.AddRaw(raw); err != nil {
		t.Fatalf("baseline streaming receipt: %v", err)
	}
	baselineLine := append(append([]byte(`{"type":"evidence_receipt","detail":`), raw...), []byte("}\n")...)
	if _, err := receipt.ExtractEvidenceReceiptsBytes(baselineLine); err != nil {
		t.Fatalf("baseline JSONL receipt: %v", err)
	}
	for _, operation := range []string{"missing", "null", "case-alias", "decimal"} {
		t.Run(operation, func(t *testing.T) {
			invalid := editSecretEgressWire(t, raw, func(fields map[string]json.RawMessage) {
				switch operation {
				case "missing":
					delete(fields, "chain_seq")
				case "null":
					fields["chain_seq"] = json.RawMessage(`null`)
				case "case-alias":
					fields["CHAIN_SEQ"] = fields["chain_seq"]
					delete(fields, "chain_seq")
				case "decimal":
					fields["chain_seq"] = json.RawMessage(`0.0`)
				}
			})
			if err := receipt.VerifyV2BytesWithKey(invalid, pub, r.Signature.SignerKeyID); err == nil {
				t.Fatal("exact-byte reader accepted invalid profile")
			}
			stream, err := receipt.NewPinnedStreamingVerifier(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.AddRaw(invalid); err == nil {
				t.Fatal("stream reader accepted invalid profile")
			}
			if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType, RawDetail: invalid}}); err == nil {
				t.Fatal("entry reader accepted invalid profile")
			}
			line := append(append([]byte(`{"type":"evidence_receipt","detail":`), invalid...), []byte("}\n")...)
			if _, err := receipt.ExtractEvidenceReceiptsBytes(line); err == nil {
				t.Fatal("JSONL reader accepted invalid profile")
			}
			path := filepath.Join(t.TempDir(), "evidence.jsonl")
			if err := os.WriteFile(path, line, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := receipt.ExtractEvidenceReceipts(path); err == nil {
				t.Fatal("file reader accepted invalid profile")
			}
		})
	}
}

func TestSecretEgressTypedContextProfile(t *testing.T) {
	t.Parallel()
	_, base := secretEgressWireFixture(t)
	for name, mutate := range map[string]func(*receipt.EvidenceReceipt){
		"timezone":           func(r *receipt.EvidenceReceipt) { r.Timestamp = r.Timestamp.In(time.FixedZone("fixture", 3600)) },
		"chain_integer":      func(r *receipt.EvidenceReceipt) { r.ChainSeq = 9007199254740992 },
		"generation_integer": func(r *receipt.EvidenceReceipt) { r.ContractGeneration = 9007199254740992 },
		"empty_delegate":     func(r *receipt.EvidenceReceipt) { r.DelegationChain = []string{""} },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("typed receipt accepted context outside wire profile")
			}
		})
	}
}

func TestEvidenceReceiptLegacyJSONBindingPreserved(t *testing.T) {
	t.Parallel()
	legacy, _ := signedReceipt(t)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string][]byte{
		"case-alias": bytes.Replace(raw, []byte(`"chain_seq":`), []byte(`"CHAIN_SEQ":`), 1),
		"unknown":    bytes.Replace(raw, []byte(`"payload_kind":`), []byte(`"unknown":true,"payload_kind":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var ordinary receipt.EvidenceReceipt
			if err := json.Unmarshal(changed, &ordinary); err != nil {
				t.Fatalf("legacy normal binding changed: %v", err)
			}
			var strict receipt.EvidenceReceipt
			err := contract.DecodeStrictJSON(changed, &strict)
			if (err != nil) != (name == "unknown") {
				t.Fatalf("legacy strict binding changed: %v", err)
			}
		})
	}
}

func secretEgressWirePublicKey(t *testing.T, value string) ed25519.PublicKey {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(decoded)
}

func TestSecretEgressRecorderRawDetailIsRequiredAndPreserved(t *testing.T) {
	t.Parallel()
	raw, r := secretEgressWireFixture(t)
	entry := recorder.Entry{
		Version: 2, Timestamp: r.Timestamp, SessionID: "proxy", Type: receipt.EvidenceEntryType,
		Transport: "forward", Summary: "wire profile fixture", Detail: json.RawMessage(raw), PrevHash: recorder.GenesisHash,
	}
	entry.Hash = recorder.ComputeHash(entry)
	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')
	entries, err := recorder.ReadEntriesFromReader(bytes.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !bytes.Equal(entries[0].RawDetail, raw) {
		t.Fatal("recorder parser did not preserve original detail bytes")
	}
	got, err := receipt.ExtractEvidenceReceiptsFromEntries(entries)
	if err != nil || len(got) != 1 {
		t.Fatalf("valid raw extraction: count=%d err=%v", len(got), err)
	}
	if err := receipt.VerifyWithKey(got[0], secretEgressWirePublicKey(t, r.Signature.SignerKeyID), r.Signature.SignerKeyID); err != nil {
		t.Fatal(err)
	}

	entries[0].RawDetail = nil
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries(entries); err == nil || !strings.Contains(err.Error(), "original RawDetail") {
		t.Fatalf("new-kind parsed-map fallback should reject: %v", err)
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType, Detail: r}}); err == nil {
		t.Fatal("new-kind programmatic fallback should reject missing original detail")
	}
	legacy, _ := signedReceipt(t)
	if got, err := receipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{{Type: receipt.EvidenceEntryType, Detail: legacy}}); err != nil || len(got) != 1 {
		t.Fatalf("old-kind programmatic fallback changed: %v", err)
	}

	// The public Detail view normalizes this benign number spelling; RawDetail
	// must retain it so the wire parser can still enforce its integer grammar.
	invalidLine := bytes.Replace(line, []byte(`"chain_seq":0`), []byte(`"chain_seq":0.0`), 1)
	invalidEntries, err := recorder.ReadEntriesFromReader(bytes.NewReader(invalidLine))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(invalidEntries[0].RawDetail, []byte(`"chain_seq":0.0`)) {
		t.Fatal("number spelling was lost from RawDetail")
	}
	if _, err := receipt.ExtractEvidenceReceiptsFromEntries(invalidEntries); err == nil {
		t.Fatal("parsed recorder ingress accepted non-profile original bytes")
	}

	for _, c := range []struct {
		name  string
		line  []byte
		valid bool
	}{{"valid", line, true}, {"invalid", invalidLine, false}} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "evidence-proxy-0.jsonl"), c.line, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := receipt.ExtractEvidenceReceiptsFromSessionDir(dir, "proxy"); (err == nil) != c.valid {
				t.Fatalf("session ingress valid=%v, err=%v", c.valid, err)
			}
		})
	}
}

func TestLegacyContainerStrictnessUnchanged(t *testing.T) {
	t.Parallel()
	legacy, _ := signedReceipt(t)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	unknown := bytes.Replace(raw, []byte(`"payload_kind":`), []byte(`"unknown":true,"payload_kind":`), 1)
	for _, c := range []struct {
		name  string
		raw   []byte
		valid bool
	}{{"valid", raw, true}, {"unknown", unknown, false}} {
		t.Run(c.name, func(t *testing.T) {
			container := append(append([]byte(`{"receipts":[`), c.raw...), []byte(`]}`)...)
			var target struct {
				Receipts []receipt.EvidenceReceipt `json:"receipts"`
			}
			decoder := json.NewDecoder(bytes.NewReader(container))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&target); (err == nil) != c.valid {
				t.Fatalf("plain strict decoder valid=%v, err=%v", c.valid, err)
			}
			if err := contract.DecodeStrictJSON(container, &target); (err == nil) != c.valid {
				t.Fatalf("generic strict decoder valid=%v, err=%v", c.valid, err)
			}
			if err := json.Unmarshal(container, &target); err != nil {
				t.Fatalf("ordinary legacy parsing changed: %v", err)
			}
		})
	}
}
