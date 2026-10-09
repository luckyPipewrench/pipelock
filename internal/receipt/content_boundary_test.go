// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// wedgedHead is the chain head that a bundle pattern matched in the base32
// view, after which every receipt was refused and required mode stopped.
const wedgedHead = "f3dba8abdbadeab439c263bc611ef39646a18bbd8e23f673c3adc471f9bd82ac"

// jsonPaths returns every schema path of t, stopping at paths the producer
// classifies Generated (their whole subtree is excluded).
func jsonPaths(t reflect.Type, prefix string, classes map[string]receiptcontent.Class, out map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) || t == reflect.TypeOf(json.RawMessage(nil)) {
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = true
			if classes[path] != receiptcontent.Generated {
				jsonPaths(f.Type, path, classes, out)
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() != reflect.Uint8 {
			out[prefix+"[]"] = true
			jsonPaths(t.Elem(), prefix+"[]", classes, out)
		}
	case reflect.Map:
		out[prefix+".*"] = true
		jsonPaths(t.Elem(), prefix+".*", classes, out)
	}
}

func TestActionReceiptSchemaCoversEveryField(t *testing.T) {
	classes := actionReceiptProducer.Classification()
	paths := map[string]bool{"ext.*": true}
	jsonPaths(reflect.TypeOf(Receipt{}), "", classes, paths)
	for path := range paths {
		if _, ok := classes[path]; !ok {
			t.Errorf("receipt path %q is not classified in actionReceiptFields", path)
		}
	}
	for path := range classes {
		if !paths[path] {
			t.Errorf("classified path %q is not a receipt field", path)
		}
	}
	for _, dyn := range []string{"ext", "action_record.redaction.by_class"} {
		if classes[dyn] != receiptcontent.Dynamic {
			t.Errorf("%s must be Dynamic so caller member names are scanned", dyn)
		}
	}
	if !receiptcontent.Registered(ActionReceiptContentKind) {
		t.Fatal("v1 kind is not registered")
	}
}

type boundaryFixture struct {
	sc   *scanner.Scanner
	rec  *recorder.Recorder
	em   *Emitter
	key  ed25519.PrivateKey
	dir  string
	pubH string
}

const boundaryCanary = "cbAa1Bb2Cc3Dd4Ee5Ff6"

// newBoundaryFixture builds a scanner-backed redacting recorder whose detector
// matches the wedged head and the test signer key, standing in for the rule
// bundle patterns that matched them, plus a configured canary.
func newBoundaryFixture(t *testing.T, extra ...string) *boundaryFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	pubH := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns,
		config.DLPPattern{Name: "dlp-phi-icd-10", Regex: wedgedHead[:24], Severity: config.SeverityHigh},
		config.DLPPattern{Name: "dlp-phi-hl7-pid", Regex: pubH[:24], Severity: config.SeverityHigh},
	)
	tokens := []config.CanaryToken{{Name: "boundary_canary", Value: boundaryCanary}}
	for i, v := range extra {
		tokens = append(tokens, config.CanaryToken{Name: "extra_" + string(rune('a'+i)), Value: v})
	}
	cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: tokens}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	dir := t.TempDir()
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: testConfigHash, Principal: testPrincipal, Actor: testActor})
	if em == nil || em.InitError() != nil {
		t.Fatalf("emitter: %v", em.InitError())
	}
	return &boundaryFixture{sc: sc, rec: rec, em: em, key: key, dir: dir, pubH: pubH}
}

func (f *boundaryFixture) receipts(t *testing.T) []Receipt {
	t.Helper()
	if err := f.rec.Close(); err != nil {
		t.Fatal(err)
	}
	rs := readReceiptsRaw(t, f.dir)
	for _, r := range rs {
		if err := VerifyWithKey(r, f.pubH); err != nil {
			t.Fatalf("VerifyWithKey: %v", err)
		}
	}
	return rs
}

func baseOpts() EmitOpts {
	return EmitOpts{ActionID: NewActionID(), Target: testTarget, Verdict: config.ActionAllow, Transport: testTransport, Method: "GET"}
}

func TestWedgedHeadAndSignerKeyNoLongerRefuseReceipts(t *testing.T) {
	f := newBoundaryFixture(t)
	// Precondition: under the old whole-receipt preflight this detector
	// refuses a signed receipt carrying the wedged head and this signer key.
	ar := f.em.contentRecord(baseOpts(), ActionRead, SideEffectExternalRead, ReversibilityFull, testConfigHash)
	ar.Timestamp = time.Now().UTC()
	ar.ChainPrevHash = wedgedHead
	signed, err := Sign(ar, f.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := Marshal(signed)
	if f.sc.ScanTextForDLP(context.Background(), string(raw)).Clean {
		t.Fatal("precondition: the bundle-equivalent detector must refuse the whole signed receipt")
	}
	const n = 50
	for i := 0; i < n; i++ {
		f.em.chainMu.Lock()
		f.em.chainPrevHash = wedgedHead
		f.em.chainMu.Unlock()
		if err := f.em.Emit(baseOpts()); err != nil {
			t.Fatalf("receipt %d with the wedged head refused: %v", i, err)
		}
	}
	rs := f.receipts(t)
	if len(rs) != n || rs[1].ActionRecord.ChainPrevHash != wedgedHead || rs[0].SignerKey != f.pubH {
		t.Fatalf("recorded %d receipts; head=%s", len(rs), rs[1].ActionRecord.ChainPrevHash)
	}
}

func TestActionContentCanaries(t *testing.T) {
	chosenUUID := uuid.Must(uuid.NewV7()).String()
	policyHex := strings.Repeat("ab12", 16)
	cases := []struct {
		name   string
		mutate func(*EmitOpts)
		reject string // field named by the rejection; "" means redacted and accepted
	}{
		{"target is sanitized", func(o *EmitOpts) { o.Target = "https://api.vendor.example/x?k=" + boundaryCanary }, ""},
		{"pattern is redacted", func(o *EmitOpts) { o.Pattern = boundaryCanary }, ""},
		{"agent label is redacted", func(o *EmitOpts) { o.Agent = boundaryCanary }, ""},
		{"policy hash override is redacted (round-2 A)", func(o *EmitOpts) { o.PolicyHash = policyHex }, ""},
		{"request id is an identity", func(o *EmitOpts) { o.RequestID = boundaryCanary }, "action_record.request_id"},
		{"chosen UUID action id is an identity (round-2 A)", func(o *EmitOpts) { o.ActionID = chosenUUID }, "action_record.action_id"},
		{"session id is an identity", func(o *EmitOpts) { o.SessionID = boundaryCanary }, "action_record.session_id"},
		{"split across task id and label (round-2 B)", func(o *EmitOpts) {
			o.SessionTaskID, o.SessionTaskLabel = boundaryCanary[:10], boundaryCanary[10:]
		}, "action_record.session_task"},
		{"extension member name", func(o *EmitOpts) { o.Extension = json.RawMessage(`{"` + boundaryCanary + `":1}`) }, "ext."},
		{"escaped extension value split from a core field", func(o *EmitOpts) {
			o.Method = boundaryCanary[:10]
			o.Extension = json.RawMessage(`{"note":"3` + boundaryCanary[11:] + `"}`)
		}, "action_record.method"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoundaryFixture(t, chosenUUID, policyHex)
			opts := baseOpts()
			tc.mutate(&opts)
			err := f.em.Emit(opts)
			if tc.reject != "" {
				if !errors.Is(err, receiptcontent.ErrRejected) || !strings.Contains(err.Error(), tc.reject) {
					t.Fatalf("err = %v, want content rejection naming %s", err, tc.reject)
				}
				if strings.Contains(err.Error(), boundaryCanary) || strings.Contains(err.Error(), chosenUUID) {
					t.Fatalf("rejection echoed the rejected value: %v", err)
				}
				if f.em.HealthError() != nil {
					t.Fatal("content rejection poisoned the emitter")
				}
				if err := f.em.Emit(baseOpts()); err != nil {
					t.Fatalf("clean receipt after rejection: %v", err)
				}
			} else if err != nil {
				t.Fatalf("redactable content refused: %v", err)
			}
			rs := f.receipts(t)
			if len(rs) != 1 {
				t.Fatalf("recorded %d receipts, want 1", len(rs))
			}
			raw, _ := Marshal(rs[0])
			if strings.Contains(string(raw), boundaryCanary) || strings.Contains(string(raw), policyHex) {
				t.Fatalf("canary reached the signed receipt: %s", raw)
			}
		})
	}
}

func TestGeneratedActionIDIsExcludedButChosenIDIsScanned(t *testing.T) {
	var seen []string
	det := func(_ context.Context, text string) scanner.TextDLPResult {
		seen = append(seen, text)
		return scanner.TextDLPResult{Clean: true}
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, det, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key})
	gen, chosen := NewActionID(), "chosen-action-id"
	if err := em.Emit(EmitOpts{ActionID: gen, ParentActionID: chosen, Target: testTarget, Verdict: config.ActionAllow, Transport: testTransport}); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(seen, "\n")
	if strings.Contains(all, gen) || !strings.Contains(all, chosen) || strings.Contains(all, "ed25519") {
		t.Fatalf("generated ID scanned=%t chosen ID scanned=%t signature scanned=%t", strings.Contains(all, gen), strings.Contains(all, chosen), strings.Contains(all, "ed25519"))
	}
}

func TestBindReceiptContentRefusesChangedContent(t *testing.T) {
	f := newBoundaryFixture(t)
	defer func() { _ = f.rec.Close() }()
	tmpl := Receipt{Version: ReceiptVersion, ActionRecord: f.em.contentRecord(baseOpts(), ActionRead, SideEffectNone, ReversibilityFull, testConfigHash)}
	raw, _ := json.Marshal(tmpl)
	_, cs, err := f.rec.ScanReceiptContent(context.Background(), actionReceiptProducer, raw)
	if err != nil || cs == nil {
		t.Fatalf("scan: %v", err)
	}
	tmpl.ActionRecord.ChainPrevHash = wedgedHead // generated: same projection
	same, _ := json.Marshal(tmpl)
	if _, err := f.rec.BindReceiptContent(cs, actionReceiptProducer, same); err != nil {
		t.Fatalf("generated stamp changed the binding: %v", err)
	}
	tmpl.ActionRecord.Target = "https://api.vendor.example/other"
	changed, _ := json.Marshal(tmpl)
	if _, err := f.rec.BindReceiptContent(cs, actionReceiptProducer, changed); !errors.Is(err, recorder.ErrContentChanged) {
		t.Fatalf("changed content bound: %v", err)
	}
	if _, err := f.rec.BindReceiptContent(nil, actionReceiptProducer, raw); err == nil {
		t.Fatal("nil scan accepted")
	}
	if _, _, err := f.rec.ScanReceiptContent(context.Background(), nil, raw); err == nil {
		t.Fatal("nil producer accepted")
	}
}
