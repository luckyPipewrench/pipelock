// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	v2WedgedHead = "f3dba8abdbadeab439c263bc611ef39646a18bbd8e23f673c3adc471f9bd82ac"
	v2Canary     = "v2Aa1Bb2Cc3Dd4Ee5Ff6"
)

func TestEvidenceReceiptSchemaCoversEnvelope(t *testing.T) {
	classes := evidenceReceiptProducer.Classification()
	typ := reflect.TypeOf(EvidenceReceipt{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		seen[name] = true
		if _, ok := classes[name]; !ok {
			t.Errorf("envelope field %q is not classified", name)
		}
	}
	for path := range classes {
		root, _, _ := strings.Cut(strings.TrimSuffix(path, "[]"), ".")
		if !seen[root] {
			t.Errorf("classified path %q is not an envelope field", path)
		}
	}
}

func v2Recorder(t *testing.T) *recorder.Recorder {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "dlp-phi-icd-10", Regex: v2WedgedHead[:24], Severity: config.SeverityHigh})
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "v2_canary", Value: v2Canary}}}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	return rec
}

func v2Detail(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"record_type": "evidence_receipt", "receipt_version": 2, "payload_kind": string(PayloadProxyDecision),
		"canonicalization": "jcs", "crit": []string{"payload"}, "event_id": receiptcontent.NewGeneratedID().String(),
		"timestamp": time.Now().UTC(), "principal": "operator", "actor": "agent",
		"signature": map[string]any{"signer_key_id": v2WedgedHead, "key_purpose": "receipt-signing", "algorithm": "ed25519", "signature": v2WedgedHead},
		"chain_seq": 7, "chain_prev_hash": v2WedgedHead, "policy_hash": "sha256:" + strings.Repeat("0", 64),
		"payload": map[string]any{"transport": "forward", "action_type": "read", "verdict": "allow", "winning_source": "policy", "target": "https://api.vendor.example/x"},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRecordEvidenceExcludesGeneratedFields(t *testing.T) {
	rec := v2Recorder(t)
	raw := v2Detail(t, nil)
	// Precondition: the old whole-detail preflight refuses this receipt.
	if _, err := rec.PreflightSignedReceiptDetail(json.RawMessage(raw)); err == nil {
		t.Fatal("precondition: the bundle-equivalent detector must refuse the whole signed receipt")
	}
	session := recorder.DefaultSessionBase
	for i := 0; i < 3; i++ {
		if err := recordEvidence(context.Background(), rec, session, raw, i%2 == 1); err != nil {
			t.Fatalf("v2 receipt with generated wedged head refused: %v", err)
		}
	}
}

func TestRecordEvidenceRejectsContentWithoutRedacting(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"payload target": func(m map[string]any) {
			m["payload"].(map[string]any)["target"] = "https://api.vendor.example/?k=" + v2Canary
		},
		"principal":                        func(m map[string]any) { m["principal"] = v2Canary },
		"chosen event id":                  func(m map[string]any) { m["event_id"] = v2Canary },
		"unknown payload member":           func(m map[string]any) { m["payload"].(map[string]any)[v2Canary] = "x" },
		"split across principal and actor": func(m map[string]any) { m["principal"], m["actor"] = v2Canary[:10], v2Canary[10:] },
		"selector split across payload field": func(m map[string]any) {
			m["selector_id"], m["payload"].(map[string]any)["rule_id"] = v2Canary[:8], v2Canary[8:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := v2Recorder(t)
			err := recordEvidence(context.Background(), rec, recorder.DefaultSessionBase, v2Detail(t, mutate), false)
			if !errors.Is(err, receiptcontent.ErrRejected) || strings.Contains(err.Error(), v2Canary) {
				t.Fatalf("err = %v, want content rejection without echo", err)
			}
			if err := recordEvidence(context.Background(), rec, recorder.DefaultSessionBase, v2Detail(t, nil), false); err != nil {
				t.Fatalf("clean receipt after rejection: %v", err)
			}
		})
	}
}

type plainRecorder struct{ entries []recorder.Entry }

func (p *plainRecorder) Record(e recorder.Entry) error { p.entries = append(p.entries, e); return nil }

func TestRecordEvidenceFallbackAndMirrorDerivation(t *testing.T) {
	p := &plainRecorder{}
	raw := v2Detail(t, nil)
	if err := recordEvidence(context.Background(), p, "s", raw, false); err != nil {
		t.Fatal(err)
	}
	if len(p.entries) != 1 || p.entries[0].Summary != "proxy_decision: read allow via policy" || p.entries[0].Transport != "forward" {
		t.Fatalf("entry = %+v", p.entries)
	}
	if err := recordEvidence(context.Background(), p, "s", raw, true); !errors.Is(err, ErrNoDurableRecorder) {
		t.Fatalf("durable on plain recorder: %v", err)
	}
	if err := recordEvidence(context.Background(), p, "s", []byte(`{`), false); err == nil {
		t.Fatal("malformed detail accepted")
	}
	shadow := v2Detail(t, func(m map[string]any) { m["payload_kind"] = string(PayloadShadowDelta) })
	if err := recordEvidence(context.Background(), p, "s", shadow, false); err != nil || p.entries[1].Summary != string(PayloadShadowDelta) {
		t.Fatalf("shadow mirror = %+v, %v", p.entries, err)
	}
}

func TestDeclaredPayloadMembersAreNotKeyCandidates(t *testing.T) {
	keys := func(detail []byte) []string {
		t.Helper()
		proj, err := evidenceReceiptProducer.Project(detail)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range proj.Atoms() {
			if a.Kind == receiptcontent.AtomKey && strings.HasPrefix(a.Path, "payload.") {
				out = append(out, a.Path)
			}
		}
		return out
	}
	// Fixed member names are not caller content, so they take no slot in the
	// bounded fragment reconstruction; their values still do.
	full := v2Detail(t, func(m map[string]any) {
		p := m["payload"].(map[string]any)
		p["live_verdict"], p["policy_sources"], p["rule_id"] = "allow", []string{"policy"}, "r1"
	})
	if got := keys(full); len(got) != 0 {
		t.Fatalf("declared payload members projected as key atoms: %v", got)
	}
	// An undeclared member name is caller content and stays a key atom.
	extra := v2Detail(t, func(m map[string]any) { m["payload"].(map[string]any)["undeclared"] = "x" })
	if got := keys(extra); len(got) != 1 {
		t.Fatalf("undeclared payload member key atoms = %v, want one", got)
	}
}
