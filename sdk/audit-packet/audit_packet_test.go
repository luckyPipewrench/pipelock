// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package auditpacket_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	auditpacket "github.com/luckyPipewrench/pipelock/sdk/audit-packet"
)

// exampleFile is the golden minimal packet that conforms to v0.json.
const exampleFile = "example.json"

// schemaFile is the locked JSON Schema this package binds to.
const schemaFile = "v0.json"

// loadExample returns the example.json bytes and parsed Packet.
func loadExample(t *testing.T) ([]byte, auditpacket.Packet) {
	t.Helper()
	path := filepath.Clean(filepath.Join(".", exampleFile))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var p auditpacket.Packet
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return data, p
}

// TestExampleConformsToV0 is the central round-trip test: the golden packet
// MUST unmarshal cleanly, MUST pass Validate(), and MUST re-marshal to a
// JSON document semantically equal to the original (allowing for whitespace
// differences only).
func TestExampleConformsToV0(t *testing.T) {
	original, p := loadExample(t)

	if err := p.Validate(); err != nil {
		t.Fatalf("example.json should validate: %v", err)
	}

	if p.SchemaVersion != auditpacket.SchemaVersion {
		t.Errorf("schema_version=%q want %q", p.SchemaVersion, auditpacket.SchemaVersion)
	}

	// Round-trip: marshal back, parse both into generic JSON, compare.
	round, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var orig, again any
	if err := json.Unmarshal(original, &orig); err != nil {
		t.Fatalf("unmarshal original generic: %v", err)
	}
	if err := json.Unmarshal(round, &again); err != nil {
		t.Fatalf("unmarshal round-trip generic: %v", err)
	}
	if !reflect.DeepEqual(orig, again) {
		t.Errorf("round-trip diverged from original\norig:\n%s\nagain:\n%s",
			string(original), string(round))
	}
}

// TestSchemaFileIsValidJSON guards against the schema file becoming malformed
// during edits. We do NOT invoke a full JSON Schema validator (that would
// require a third-party dep). The schema's job is enforced externally; here we
// only verify it parses and declares the v0 $id we expect.
func TestSchemaFileIsValidJSON(t *testing.T) {
	path := filepath.Clean(filepath.Join(".", schemaFile))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", schemaFile, err)
	}
	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("unmarshal %s: %v", schemaFile, err)
	}
	gotID, _ := meta["$id"].(string)
	wantID := "https://pipelab.org/schemas/audit-packet-v0.schema.json"
	if gotID != wantID {
		t.Errorf("$id = %q want %q", gotID, wantID)
	}
	gotTitle, _ := meta["title"].(string)
	if !strings.Contains(gotTitle, "Audit Packet v0") {
		t.Errorf("title = %q must mention Audit Packet v0", gotTitle)
	}
}

// TestTotalsKeys verifies the locked v0 bucket set. Adding or removing a
// bucket would silently break consumers and would belong in a v1 schema, not
// a v0 patch.
func TestTotalsKeys(t *testing.T) {
	got := auditpacket.TotalsKeys()
	want := []string{"allow", "block", "warn", "ask", "strip", "forward", "redirect", "other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TotalsKeys = %v want %v", got, want)
	}

	// Mutating the returned slice MUST NOT affect future calls.
	got[0] = "tampered"
	again := auditpacket.TotalsKeys()
	if again[0] != "allow" {
		t.Errorf("TotalsKeys returned aliased slice; mutation leaked: %v", again)
	}
}

// TestValidate covers the validator's contract: valid packets pass, malformed
// packets fail with informative errors. Each row is one mutation of the
// golden packet.
func TestValidate(t *testing.T) {
	_, base := loadExample(t)

	cases := []struct {
		name    string
		mutate  func(*auditpacket.Packet)
		wantSub string
	}{
		{
			name:    "valid example",
			mutate:  func(*auditpacket.Packet) {},
			wantSub: "",
		},
		{
			name:    "wrong schema_version",
			mutate:  func(p *auditpacket.Packet) { p.SchemaVersion = "pipelock.audit_packet.v1" },
			wantSub: "schema_version",
		},
		{
			name:    "missing generated_at",
			mutate:  func(p *auditpacket.Packet) { p.GeneratedAt = "" },
			wantSub: "generated_at",
		},
		{
			name:    "unknown provider",
			mutate:  func(p *auditpacket.Packet) { p.Run.Provider = "jenkins" },
			wantSub: "provider",
		},
		{
			name:    "missing agent_identity",
			mutate:  func(p *auditpacket.Packet) { p.Run.AgentIdentity = "" },
			wantSub: "agent_identity",
		},
		{
			name:    "missing started_at",
			mutate:  func(p *auditpacket.Packet) { p.Run.StartedAt = "" },
			wantSub: "started_at",
		},
		{
			name:    "policy_hashes nil rejected",
			mutate:  func(p *auditpacket.Packet) { p.Policy.PolicyHashes = nil },
			wantSub: "policy_hashes",
		},
		{
			name:    "negative totals bucket",
			mutate:  func(p *auditpacket.Packet) { p.Summary.Totals.Block = -1 },
			wantSub: "totals counts",
		},
		{
			name:    "totals sum mismatch",
			mutate:  func(p *auditpacket.Packet) { p.Summary.Totals.Allow++ },
			wantSub: "totals sum",
		},
		{
			name:    "negative receipt_count",
			mutate:  func(p *auditpacket.Packet) { p.Summary.ReceiptCount = -1 },
			wantSub: "receipt_count",
		},
		{
			name:    "negative transport count",
			mutate:  func(p *auditpacket.Packet) { p.Summary.Transports["https"] = -1 },
			wantSub: "transports",
		},
		{
			name:    "negative layer count",
			mutate:  func(p *auditpacket.Packet) { p.Summary.Layers["dlp"] = -1 },
			wantSub: "layers",
		},
		{
			name: "domains_touched must be sorted",
			mutate: func(p *auditpacket.Packet) {
				p.Summary.DomainsTouched = []string{"z.example", "a.example"}
			},
			wantSub: "domains_touched must be sorted",
		},
		{
			name: "domains_touched must be unique",
			mutate: func(p *auditpacket.Packet) {
				p.Summary.DomainsTouched = []string{"a.example", "a.example"}
			},
			wantSub: "domains_touched contains duplicate",
		},
		{
			name:    "unknown verdict",
			mutate:  func(p *auditpacket.Packet) { p.Verifier.Verdict = "ok" },
			wantSub: "verdict",
		},
		{
			name: "valid verdict requires trusted",
			mutate: func(p *auditpacket.Packet) {
				p.Verifier.Verdict = auditpacket.VerdictValid
				p.Verifier.Trusted = false
			},
			wantSub: "verdict=valid requires trusted=true",
		},
		{
			name: "trusted=true with self_consistent_only is rejected",
			mutate: func(p *auditpacket.Packet) {
				p.Verifier.Verdict = auditpacket.VerdictSelfConsistentOnly
				p.Verifier.Trusted = true
			},
			wantSub: "trusted=true requires verdict=valid",
		},
		{
			name: "trusted=true requires signer_key",
			mutate: func(p *auditpacket.Packet) {
				p.Verifier.SignerKey = ""
			},
			wantSub: "trusted=true requires signer_key",
		},
		{
			name:    "negative verifier receipt_count",
			mutate:  func(p *auditpacket.Packet) { p.Verifier.ReceiptCount = -1 },
			wantSub: "receipt_count",
		},
		{
			name:    "negative final_seq",
			mutate:  func(p *auditpacket.Packet) { p.Verifier.FinalSeq = -1 },
			wantSub: "final_seq",
		},
		{
			name: "invalid inline receipt",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{}}
			},
			wantSub: "receipts[0]",
		},
		{
			name: "inline receipt missing receipt_hash",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:      "a",
					ChainSeq:      0,
					ChainPrevHash: "genesis",
					Verdict:       "allow",
					PolicyHash:    "sha256:test",
				}}
			},
			wantSub: "receipt_hash",
		},
		{
			name: "invalid inline receipt chain seq",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:      "a",
					ReceiptHash:   "h",
					ChainSeq:      -1,
					ChainPrevHash: "genesis",
					Verdict:       "allow",
					PolicyHash:    "sha256:test",
				}}
			},
			wantSub: "chain_seq",
		},
		{
			name: "inline receipt missing chain_prev_hash",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:    "a",
					ReceiptHash: "h",
					ChainSeq:    0,
					Verdict:     "allow",
					PolicyHash:  "sha256:test",
				}}
			},
			wantSub: "chain_prev_hash",
		},
		{
			name: "inline receipt missing verdict",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:      "a",
					ReceiptHash:   "h",
					ChainSeq:      0,
					ChainPrevHash: "genesis",
					PolicyHash:    "sha256:test",
				}}
			},
			wantSub: "verdict",
		},
		{
			name: "inline receipt missing policy_hash",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:      "a",
					ReceiptHash:   "h",
					ChainSeq:      0,
					ChainPrevHash: "genesis",
					Verdict:       "allow",
				}}
			},
			wantSub: "policy_hash",
		},
		{
			name: "valid inline receipt",
			mutate: func(p *auditpacket.Packet) {
				p.Receipts = []auditpacket.Receipt{{
					ActionID:      "a",
					ReceiptHash:   "h",
					ChainSeq:      0,
					ChainPrevHash: "genesis",
					Verdict:       "allow",
					PolicyHash:    "sha256:test",
				}}
			},
			wantSub: "",
		},
		{
			name: "valid scanner config snapshot",
			mutate: func(p *auditpacket.Packet) {
				truthy := true
				p.ScannerConfigSnapshot = &auditpacket.ScannerConfigSnapshot{
					DLPPatternsCount:      1,
					ResponsePatternsCount: 2,
					SSRFEnabled:           &truthy,
					RedactionEnabled:      &truthy,
					FlightRecorderEnabled: &truthy,
				}
			},
			wantSub: "",
		},
		{
			name: "negative scanner config count",
			mutate: func(p *auditpacket.Packet) {
				p.ScannerConfigSnapshot = &auditpacket.ScannerConfigSnapshot{DLPPatternsCount: -1}
			},
			wantSub: "dlp_patterns_count",
		},
		{
			name: "negative scanner response count",
			mutate: func(p *auditpacket.Packet) {
				p.ScannerConfigSnapshot = &auditpacket.ScannerConfigSnapshot{ResponsePatternsCount: -1}
			},
			wantSub: "response_patterns_count",
		},
		{
			name:    "missing enforcement_mode",
			mutate:  func(p *auditpacket.Packet) { p.Posture.EnforcementMode = "" },
			wantSub: "enforcement_mode",
		},
		{
			name:    "missing runner_os",
			mutate:  func(p *auditpacket.Packet) { p.Posture.RunnerOS = "" },
			wantSub: "runner_os",
		},
		{
			name:    "invalid raw_socket_status",
			mutate:  func(p *auditpacket.Packet) { p.Posture.RawSocketStatus = "" },
			wantSub: "raw_socket_status",
		},
		{
			name:    "invalid docker_socket_status",
			mutate:  func(p *auditpacket.Packet) { p.Posture.DockerSocketStatus = "mounted" },
			wantSub: "docker_socket_status",
		},
		{
			name:    "invalid dns_udp_status",
			mutate:  func(p *auditpacket.Packet) { p.Posture.DNSUDPStatus = "blocked" },
			wantSub: "dns_udp_status",
		},
		{
			name:    "invalid browser_proxy_status",
			mutate:  func(p *auditpacket.Packet) { p.Posture.BrowserProxyStatus = "enabled" },
			wantSub: "browser_proxy_status",
		},
		{
			name:    "invalid websocket_frame_scanning",
			mutate:  func(p *auditpacket.Packet) { p.Posture.WebsocketFrameScanning = "unknown" },
			wantSub: "websocket_frame_scanning",
		},
		{
			name:    "negative script_arg_count",
			mutate:  func(p *auditpacket.Packet) { p.Posture.ScriptArgCount = -1 },
			wantSub: "script_arg_count",
		},
		{
			name:    "unsupported_paths nil rejected",
			mutate:  func(p *auditpacket.Packet) { p.Posture.UnsupportedPaths = nil },
			wantSub: "unsupported_paths",
		},
		{
			name:    "missing artifacts.packet",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Packet = "" },
			wantSub: "packet path",
		},
		{
			name:    "missing artifacts.evidence",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Evidence = "" },
			wantSub: "evidence path",
		},
		{
			name:    "missing artifacts.verifier",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Verifier = "" },
			wantSub: "verifier path",
		},
		{
			name:    "absolute artifact path rejected",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Evidence = "/tmp/evidence.jsonl" },
			wantSub: "evidence path must be relative",
		},
		{
			name:    "windows artifact path rejected",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Packet = `C:\tmp\packet.json` },
			wantSub: "packet path must be slash-relative",
		},
		{
			name:    "traversal artifact path rejected",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Verifier = "../verifier.txt" },
			wantSub: "verifier path must stay inside",
		},
		{
			name:    "optional summary artifact may be empty",
			mutate:  func(p *auditpacket.Packet) { p.Artifacts.Summary = "" },
			wantSub: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := clonePacket(t, base)
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("expected valid, got err: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %q want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateNilPacket covers the nil-receiver path explicitly so the
// 95% coverage target on this file holds.
func TestValidateNilPacket(t *testing.T) {
	var p *auditpacket.Packet
	err := p.Validate()
	if err == nil {
		t.Fatalf("nil packet must fail validation")
	}
	if !strings.Contains(err.Error(), "nil packet") {
		t.Errorf("err = %q want substring %q", err.Error(), "nil packet")
	}
}

// TestSortedDomains exercises the helper that producers SHOULD use to make
// summary.domains_touched byte-deterministic.
func TestSortedDomains(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", in: nil, want: nil},
		{name: "empty slice", in: []string{}, want: nil},
		{
			name: "dedupes and sorts",
			in:   []string{"github.com", "api.anthropic.com", "github.com", "registry.npmjs.org"},
			want: []string{"api.anthropic.com", "github.com", "registry.npmjs.org"},
		},
		{
			name: "single",
			in:   []string{"only.example"},
			want: []string{"only.example"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := auditpacket.SortedDomains(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SortedDomains(%v) = %v want %v", tc.in, got, tc.want)
			}
			if got != nil && !sort.StringsAreSorted(got) {
				t.Errorf("SortedDomains output not sorted: %v", got)
			}
		})
	}
}

// TestExampleEmitsAllTotalsKeys guards the producer convention: the example
// packet (and any real packet) MUST include all eight totals keys, even when
// zero.
func TestExampleEmitsAllTotalsKeys(t *testing.T) {
	data, _ := loadExample(t)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	summary, ok := raw["summary"]
	if !ok {
		t.Fatalf("missing summary")
	}
	var sumMap map[string]json.RawMessage
	if err := json.Unmarshal(summary, &sumMap); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	totalsRaw, ok := sumMap["totals"]
	if !ok {
		t.Fatalf("missing summary.totals")
	}
	var totals map[string]int
	if err := json.Unmarshal(totalsRaw, &totals); err != nil {
		t.Fatalf("unmarshal totals: %v", err)
	}
	for _, key := range auditpacket.TotalsKeys() {
		if _, present := totals[key]; !present {
			t.Errorf("example.json totals missing required key %q", key)
		}
	}
	if len(totals) != len(auditpacket.TotalsKeys()) {
		t.Errorf("example.json totals has %d keys, want exactly %d (%v)",
			len(totals), len(auditpacket.TotalsKeys()), auditpacket.TotalsKeys())
	}
}

// clonePacket returns a deep copy of p by JSON round-trip. Sufficient for the
// small fixture sizes here.
func clonePacket(t *testing.T, p auditpacket.Packet) auditpacket.Packet {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(p); err != nil {
		t.Fatalf("clone marshal: %v", err)
	}
	var out auditpacket.Packet
	if err := json.NewDecoder(&buf).Decode(&out); err != nil {
		t.Fatalf("clone unmarshal: %v", err)
	}
	return out
}
