// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestEmitterSanitationUnknownRedactorFallback(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var changed atomic.Bool
	redactor := func(ctx context.Context, text string) scanner.TextDLPResult {
		return scanner.TextDLPResult{Clean: !changed.Load() || !strings.Contains(text, "rotating-secret-value")}
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, Redact: true}, redactor, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, known := rec.ImmutableReceiptRedactor(); known {
		t.Fatal("arbitrary callback acquired immutable guarantee")
	}
	em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key})
	em.beforeChainLockForTest = func() { changed.Store(true) }
	if err := em.EmitDurable(EmitOpts{ActionID: "fallback", Target: "https://api.vendor.example/item?q=rotating-secret-value", Transport: "intercept", Method: "GET", Verdict: config.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	r := readReceiptFromDir(t, dir, key.Public().(ed25519.PublicKey))
	if strings.Contains(r.ActionRecord.Target, "rotating-secret-value") || !strings.Contains(strings.ToLower(r.ActionRecord.Target), "redacted") {
		t.Fatalf("target=%q", r.ActionRecord.Target)
	}
	t.Log("unknown mutable callback uses current locked sanitation; signature verifies PASS")
}

func TestEmitterSanitationBoundGeneration(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	old := scanner.MustNew(cfg)
	defer old.Close()
	cfg2 := config.Defaults()
	cfg2.Internal = nil
	cfg2.DLP.Patterns = append(cfg2.DLP.Patterns, config.DLPPattern{Name: "generation signal", Regex: "generation-signal", Severity: config.SeverityHigh})
	newer := scanner.MustNew(cfg2)
	defer newer.Close()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, old, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	rf, known := rec.ImmutableReceiptRedactor()
	if !known || rf == nil {
		t.Fatal("bound generation missing")
	}
	if !rf(context.Background(), "generation-signal").Clean {
		t.Fatal("old detector unexpectedly matches")
	}
	if newer.ScanTextForDLPQuiet(context.Background(), "generation-signal").Clean {
		t.Fatal("new generation positive control failed")
	}
	if !rf(context.Background(), "generation-signal").Clean {
		t.Fatal("recorder silently adopted new generation")
	}
	if _, err := recorder.NewWithScanner(recorder.Config{Redact: true}, nil, key); err == nil {
		t.Fatal("nil generation silently disables redaction")
	}
	t.Log("immutable scanner binding/new-generation positive/nil-detector fail-closed PASS")
}

func TestEmitterSanitationOutsideChain(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "sanitation warning", Regex: "sanitation-signal", Action: config.ActionWarn, Severity: config.SeverityHigh})
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	seen := make(chan struct{}, 1)
	sc.SetDLPWarnHook(func(context.Context, string, string) {
		select {
		case seen <- struct{}{}:
		default:
		}
	})
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: t.TempDir(), Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key})
	em.chainMu.Lock()
	done := make(chan error, 1)
	go func() {
		done <- em.Emit(EmitOpts{ActionID: "outside", Target: "https://api.vendor.example/?q=sanitation-signal", Transport: "intercept", Method: "GET", Verdict: config.ActionAllow})
	}()
	select {
	case <-seen:
	case <-time.After(2 * time.Second):
		em.chainMu.Unlock()
		<-done
		t.Fatal("sanitation stayed behind chain lock")
	}
	em.chainMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEmitterSanitationSignedParity(t *testing.T) {
	var outputs [][]byte
	for _, bound := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Internal = nil
		sc := scanner.MustNew(cfg)
		defer sc.Close()
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		pub := key.Public().(ed25519.PublicKey)
		dir := t.TempDir()
		recCfg := recorder.Config{Enabled: true, Dir: dir, Redact: true, CheckpointInterval: 1000, SignCheckpoints: true}
		var rec *recorder.Recorder
		var err error
		if bound {
			rec, err = recorder.NewWithScanner(recCfg, sc, key)
		} else {
			rec, err = recorder.New(recCfg, sc.ScanTextForDLP, key)
		}
		if err != nil {
			t.Fatal(err)
		}
		em := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, ConfigHash: cfg.CanonicalPolicyHash()})
		em.runNonce = strings.Repeat("a", 32)
		em.now = func() time.Time { return time.Unix(1700000000, 0) }
		if err := em.EmitDurable(EmitOpts{ActionID: "parity-open", Verdict: config.ActionAllow, Transport: sessionControlTransport, Target: sessionOpenTarget, SessionControl: &SessionControl{Kind: SessionControlOpen, Open: &SessionOpen{OpenNonce: strings.Repeat("b", 32)}}}); err != nil {
			t.Fatal(err)
		}
		for i, target := range []string{"https://api.vendor.example/clean?q=ordinary", "https://api.vendor.example/query?token=" + "ghp_" + strings.Repeat("A", 36), "https://api.vendor.example/encoded?q=%67%68%70%5f" + strings.Repeat("A", 36), "opaque-target"} {
			opts := EmitOpts{ActionID: fmt.Sprintf("parity-%d", i), Target: target, Pattern: "ghp_" + strings.Repeat("B", 36), Method: "GET", Transport: "intercept", Verdict: config.ActionAllow}
			if err := em.EmitDurable(opts); err != nil {
				t.Fatal(err)
			}
		}
		if err := rec.Close(); err != nil {
			t.Fatal(err)
		}
		rs := readAllReceiptsFromDir(t, dir, pub)
		if v := VerifyChain(rs, hex.EncodeToString(pub)); !v.Valid {
			t.Fatal(v)
		}
		var bytes []byte
		for _, r := range rs {
			b, e := Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			bytes = append(bytes, b...)
			bytes = append(bytes, '\n')
		}
		outputs = append(outputs, bytes)
	}
	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatal("bound sanitation changed signed receipt bytes")
	}
}
