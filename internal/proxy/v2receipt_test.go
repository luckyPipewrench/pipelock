// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// --- Unit tests for the EmitOpts -> v2 Decision derivation ---

func TestV2DecisionFromOpts_Provenance(t *testing.T) {
	tests := []struct {
		name        string
		opts        receipt.EmitOpts
		wantOK      bool
		wantAction  string
		wantWinning string
		wantSources []string
		wantStamped bool
	}{
		{
			name:        "scanner block",
			opts:        receipt.EmitOpts{Transport: TransportFetch, Target: "https://x.example/a", Verdict: "block", Layer: "dlp", Pattern: "aws_key", Method: "GET"},
			wantOK:      true,
			wantAction:  v2ActionHTTPRequest,
			wantWinning: proxydecision.SourceScanner,
			wantSources: []string{proxydecision.SourceScanner},
		},
		{
			name:        "kill switch block",
			opts:        receipt.EmitOpts{Transport: TransportConnect, Target: "host:443", Verdict: "block", Layer: killSwitchLayer, Pattern: "kill_switch_active"},
			wantOK:      true,
			wantAction:  v2ActionHTTPRequest,
			wantWinning: proxydecision.SourceKillSwitch,
			wantSources: []string{proxydecision.SourceKillSwitch},
		},
		{
			name: "contract decision stamps envelope and adds contract source",
			opts: receipt.EmitOpts{
				Transport: TransportForward, Target: "https://x.example/c", Verdict: "block", Method: "POST",
				ContractWinningSource: "manifest", ContractPolicySources: []string{"observation"},
				ContractRuleID: "rule-7", ActiveManifestHash: "sha256:m", ContractHash: "sha256:c",
				ContractSelectorID: "sel", ContractGeneration: 4,
			},
			wantOK:      true,
			wantAction:  v2ActionHTTPRequest,
			wantWinning: "manifest",
			wantSources: []string{"observation", proxydecision.SourceContract},
			wantStamped: true,
		},
		{
			name:        "mcp tool call action type",
			opts:        receipt.EmitOpts{Transport: "mcp_http", Target: "tool://do_thing", Verdict: "block", ToolName: "do_thing", MCPMethod: "tools/call", Pattern: "poison"},
			wantOK:      true,
			wantAction:  v2ActionMCPToolCall,
			wantWinning: proxydecision.SourceScanner,
			wantSources: []string{proxydecision.SourceScanner},
		},
		{
			name:        "websocket frame action type",
			opts:        receipt.EmitOpts{Transport: TransportWS, Target: "wss://x.example/ws", Verdict: "block", Pattern: "inj"},
			wantOK:      true,
			wantAction:  v2ActionWebSocketFrame,
			wantWinning: proxydecision.SourceScanner,
			wantSources: []string{proxydecision.SourceScanner},
		},
		{
			name:   "empty target is not emittable",
			opts:   receipt.EmitOpts{Transport: TransportFetch, Target: "", Verdict: "block"},
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, ok := v2DecisionFromOpts(tc.opts)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if d.ActionType != tc.wantAction {
				t.Errorf("ActionType = %q, want %q", d.ActionType, tc.wantAction)
			}
			if d.WinningSource != tc.wantWinning {
				t.Errorf("WinningSource = %q, want %q", d.WinningSource, tc.wantWinning)
			}
			if strings.Join(d.PolicySources, ",") != strings.Join(tc.wantSources, ",") {
				t.Errorf("PolicySources = %v, want %v", d.PolicySources, tc.wantSources)
			}
			stamped := d.ActiveManifestHash != "" || d.ContractHash != "" || d.SelectorID != "" || d.ContractGeneration != 0
			if stamped != tc.wantStamped {
				t.Errorf("stamped = %v, want %v", stamped, tc.wantStamped)
			}
		})
	}
}

func TestEnsureSource(t *testing.T) {
	tests := []struct {
		in   []string
		want string
		out  []string
	}{
		{nil, "contract", []string{"contract"}},
		{[]string{"observation"}, "contract", []string{"observation", "contract"}},
		{[]string{"contract"}, "contract", []string{"contract"}},
		{[]string{"a", "contract", "b"}, "contract", []string{"a", "contract", "b"}},
	}
	for _, tc := range tests {
		got := ensureSource(tc.in, tc.want)
		if strings.Join(got, ",") != strings.Join(tc.out, ",") {
			t.Errorf("ensureSource(%v,%q) = %v, want %v", tc.in, tc.want, got, tc.out)
		}
	}
}

// --- Integration: dual-emit through a real recorder ---

// v2Entry is a minimal view of a recorder JSONL line for v2 assertions.
type v2Entry struct {
	Type      string          `json:"type"`
	EventKind string          `json:"event_kind"`
	Transport string          `json:"transport"`
	Detail    json.RawMessage `json:"detail"`
}

func readRecorderEntries(t *testing.T, dir string) []v2Entry {
	t.Helper()
	des, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var out []v2Entry
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		data, rErr := os.ReadFile(filepath.Clean(filepath.Join(dir, de.Name())))
		if rErr != nil {
			t.Fatalf("ReadFile: %v", rErr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e v2Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("unmarshal entry: %v", err)
			}
			out = append(out, e)
		}
	}
	return out
}

// dualEmitFixture wires a recorder plus both emitters from one key, the way the
// startup path does, and returns a proxy whose emitReceipt dual-emits.
type dualEmitFixture struct {
	p   *Proxy
	rec *recorder.Recorder
	dir string
	pub ed25519.PublicKey
	kid string
}

func newDualEmitFixture(t *testing.T, redact bool) *dualEmitFixture {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)

	var redactFn recorder.RedactFunc
	if redact {
		redactFn = sc.ScanTextForDLP
	}
	rec, err := recorder.New(recorder.Config{
		Enabled: true, Dir: dir, CheckpointInterval: 1000, Redact: redact,
	}, redactFn, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	v1 := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: priv, ConfigHash: "test-hash",
		Principal: "local", Actor: "pipelock",
	})
	signer := proxydecision.NewKeyedSigner(priv)
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: rec, Signer: signer,
		Sanitize:  proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()),
		Principal: "local", Actor: "pipelock",
	})
	if v1 == nil || v2 == nil {
		t.Fatal("emitter construction returned nil")
	}

	p, err := New(cfg, audit.NewNop(), sc, metrics.New(),
		WithRecorder(rec), WithReceiptEmitter(v1), WithV2ReceiptEmitter(v2))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	return &dualEmitFixture{p: p, rec: rec, dir: dir, pub: pub, kid: signer.KeyID()}
}

func (f *dualEmitFixture) v2Receipt(t *testing.T) contractreceipt.EvidenceReceipt {
	t.Helper()
	if err := f.rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	var v1Count, v2Count int
	var rcpt contractreceipt.EvidenceReceipt
	for _, e := range readRecorderEntries(t, f.dir) {
		switch e.Type {
		case "action_receipt":
			v1Count++
		case "evidence_receipt":
			if e.EventKind == string(contractreceipt.PayloadProxyDecision) {
				v2Count++
				if err := json.Unmarshal(e.Detail, &rcpt); err != nil {
					t.Fatalf("unmarshal v2 receipt: %v", err)
				}
			}
		}
	}
	if v1Count != 1 {
		t.Errorf("v1 action_receipt count = %d, want 1 (dual-emit must keep v1)", v1Count)
	}
	if v2Count != 1 {
		t.Fatalf("v2 proxy_decision count = %d, want 1", v2Count)
	}
	return rcpt
}

func TestDualEmit_ProducesVerifiableV2AlongsideV1(t *testing.T) {
	f := newDualEmitFixture(t, false)
	f.p.emitReceipt(receipt.EmitOpts{
		ActionID: "a1", Transport: TransportForward, Method: "GET",
		Target: "https://api.vendor.example/v1/x", Verdict: "block",
		Layer: "dlp", Pattern: "prompt_injection", RequestID: "r1",
	})

	rcpt := f.v2Receipt(t)
	if err := contractreceipt.VerifyWithKey(rcpt, f.pub, f.kid); err != nil {
		t.Fatalf("v2 receipt failed offline verify: %v", err)
	}
	var p contractreceipt.PayloadProxyDecisionStruct
	if err := json.Unmarshal(rcpt.Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.ActionType != v2ActionHTTPRequest || p.Transport != TransportForward {
		t.Errorf("payload surface fields wrong: %+v", p)
	}
	if p.WinningSource != proxydecision.SourceScanner {
		t.Errorf("winning_source = %q, want scanner", p.WinningSource)
	}
}

func TestDualEmit_SanitizesV2TargetWithRedaction(t *testing.T) {
	const secret = "AKIA" + "IOSFODNN7EXAMPLE"
	f := newDualEmitFixture(t, true)
	f.p.emitReceipt(receipt.EmitOpts{
		ActionID: "a1", Transport: TransportForward, Method: "GET",
		Target: "https://api.vendor.example/v1/x?key=" + secret, Verdict: "block",
		Layer: "dlp", Pattern: "aws_access_key", RequestID: "r1",
	})

	rcpt := f.v2Receipt(t)
	if err := contractreceipt.VerifyWithKey(rcpt, f.pub, f.kid); err != nil {
		t.Fatalf("v2 receipt failed offline verify: %v", err)
	}
	if strings.Contains(string(rcpt.Payload), secret) {
		t.Errorf("v2 receipt payload leaks secret: %s", rcpt.Payload)
	}
}

func TestDualEmit_DisabledWhenNoV2Emitter(t *testing.T) {
	// A proxy with only the v1 emitter must not panic and must emit no v2 entry.
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.New(cfg)
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	v1 := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "local", Actor: "pipelock"})
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithRecorder(rec), WithReceiptEmitter(v1))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	p.emitReceipt(receipt.EmitOpts{
		ActionID: "a1", Transport: TransportFetch, Method: "GET",
		Target: "https://x.example/a", Verdict: "allow", RequestID: "r1",
	})
	_ = rec.Close()
	for _, e := range readRecorderEntries(t, dir) {
		if e.Type == "evidence_receipt" && e.EventKind == string(contractreceipt.PayloadProxyDecision) {
			t.Error("v2 proxy_decision emitted despite no v2 emitter configured")
		}
	}
}

// TestDualEmit_HotReloadPreservesV2Chain proves the v2 proxy_decision chain
// stays continuous across a hot reload that rebuilds the emitter (e.g. key
// rotation), satisfying the "hot reload preserves security state" invariant.
func TestDualEmit_HotReloadPreservesV2Chain(t *testing.T) {
	recDir := t.TempDir()
	keyDir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyPath := filepath.Join(keyDir, "receipt.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}

	rec, err := recorder.New(recorder.Config{
		Enabled: true, Dir: recDir, CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FlightRecorder.SigningKeyPath = keyPath
	sc := scanner.New(cfg)

	v1 := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "local", Actor: "pipelock"})
	signer := proxydecision.NewKeyedSigner(priv)
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder: rec, Signer: signer, Principal: "local", Actor: "pipelock",
	})
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(),
		WithRecorder(rec), WithReceiptEmitter(v1), WithV2ReceiptEmitter(v2),
		WithReceiptKeyPath(keyPath))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	opts := receipt.EmitOpts{
		ActionID: "a1", Transport: TransportForward, Method: "GET",
		Target: "https://x.example/a", Verdict: "allow", RequestID: "r1",
	}
	p.emitReceipt(opts) // v2 seq 0

	// Hot reload with the same signing key; buildReceiptEmitter must carry the
	// v2 chain head forward instead of resetting to genesis.
	reloadCfg := config.Defaults()
	reloadCfg.Internal = nil
	reloadCfg.FlightRecorder.SigningKeyPath = keyPath
	if !p.Reload(reloadCfg, scanner.New(reloadCfg)) {
		t.Fatal("Reload returned false")
	}

	if p.v2EmitterPtr.Load() == nil {
		t.Fatal("v2 emitter nil after reload with signing key")
	}
	p.emitReceipt(opts) // v2 seq 1, chained to seq 0

	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	var v2s []contractreceipt.EvidenceReceipt
	for _, e := range readRecorderEntries(t, recDir) {
		if e.Type == "evidence_receipt" && e.EventKind == string(contractreceipt.PayloadProxyDecision) {
			var r contractreceipt.EvidenceReceipt
			if err := json.Unmarshal(e.Detail, &r); err != nil {
				t.Fatalf("unmarshal v2 receipt: %v", err)
			}
			v2s = append(v2s, r)
		}
	}
	if len(v2s) != 2 {
		t.Fatalf("got %d v2 receipts across reload, want 2", len(v2s))
	}
	for i, r := range v2s {
		if err := contractreceipt.VerifyWithKey(r, pub, signer.KeyID()); err != nil {
			t.Fatalf("v2 receipt %d verify: %v", i, err)
		}
		if r.ChainSeq != uint64(i) {
			t.Errorf("receipt %d ChainSeq = %d, want %d (chain reset on reload)", i, r.ChainSeq, i)
		}
	}
	h0, err := contractreceipt.ReceiptHash(v2s[0])
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	if v2s[1].ChainPrevHash != h0 {
		t.Errorf("post-reload receipt ChainPrevHash = %q, want %q (chain broke across reload)", v2s[1].ChainPrevHash, h0)
	}
}

// TestDualEmit_V1FailureSkipsV2 proves v1 stays authoritative: when the v1
// emitter rejects (here, a sealed chain), no v2 proxy_decision is written, so a
// v2 receipt never outlives its v1 action_receipt sibling.
func TestDualEmit_V1FailureSkipsV2(t *testing.T) {
	f := newDualEmitFixture(t, false)
	v1 := f.p.receiptEmitterPtr.Load()
	// Seed one v1 receipt directly (no v2) so the chain is non-empty, then seal
	// it. A sealed chain makes the next v1 Emit return ErrChainSealed.
	if err := v1.Emit(receipt.EmitOpts{
		ActionID: "seed", Transport: TransportForward, Method: "GET",
		Target: "https://x.example/seed", Verdict: "allow",
	}); err != nil {
		t.Fatalf("seed Emit: %v", err)
	}
	if err := v1.EmitTranscriptRoot("proxy"); err != nil {
		t.Fatalf("EmitTranscriptRoot: %v", err)
	}

	// This decision's v1 Emit fails (sealed); v2 must be skipped.
	f.p.emitReceipt(receipt.EmitOpts{
		ActionID: "a1", Transport: TransportForward, Method: "GET",
		Target: "https://x.example/a", Verdict: "block",
		Layer: "dlp", Pattern: "inj", RequestID: "r1",
	})
	if err := f.rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	for _, e := range readRecorderEntries(t, f.dir) {
		if e.Type == "evidence_receipt" && e.EventKind == string(contractreceipt.PayloadProxyDecision) {
			t.Error("v2 proxy_decision emitted after v1 failed; v1 must stay authoritative")
		}
	}
}
