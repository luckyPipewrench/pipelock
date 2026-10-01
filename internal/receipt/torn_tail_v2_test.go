// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestValidateEvidenceEntryV2(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: t.TempDir()}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	emitter := proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(key), Principal: "local", Actor: "pipelock", Session: "proxy"})
	if err := emitter.Emit(proxydecision.Decision{ActionType: "http_request", Transport: "forward", Target: "https://api.vendor.example/resource", Verdict: "allow", WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner}, PolicyHash: "sha256:" + strings.Repeat("0", 64)}); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(rec.Dir(), "evidence-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	entries, err := recorder.ReadEntries(files[0])
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{fmt.Sprintf("%x", key.Public())}
	if err := receipt.ValidateEvidenceEntry(entries[0], keys); err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateEvidenceEntry(entries[0], nil); err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateEvidenceEntry(entries[0], []string{"other"}); err == nil {
		t.Fatal("foreign signer accepted")
	}
	var r contractreceipt.EvidenceReceipt
	if err := json.Unmarshal(entries[0].RawDetail, &r); err != nil {
		t.Fatal(err)
	}
	r.Signature.Signature = "ed25519:" + strings.Repeat("0", 128)
	entries[0].Detail, entries[0].RawDetail = r, nil
	if err := receipt.ValidateEvidenceEntry(entries[0], keys); err == nil {
		t.Fatal("bad signature accepted")
	}
	entries[0].Detail = json.RawMessage(`{`)
	if err := receipt.ValidateEvidenceEntry(entries[0], nil); err == nil {
		t.Fatal("malformed v2 accepted")
	}
}
