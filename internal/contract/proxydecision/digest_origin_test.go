// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxydecision

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/digestorigin"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestComputedContractDigestsDoNotRefuseProxyDecisions(t *testing.T) {
	requireComputedContractDigestsRecorded(t)
}

// TestComputedDigestsSurviveUnrelatedOrigins is the regression for a bounded
// process-wide origin record: after 4096 unrelated computed digests, new
// origins were discarded and the scanner-backed emitter refused computed
// contract and manifest hashes again. Origins now live with their holders,
// so no number of unrelated digests can crowd them out.
func TestComputedDigestsSurviveUnrelatedOrigins(t *testing.T) {
	issuer := digestorigin.NewIssuer("proxydecision.test.unrelated")
	for i := 0; i < 2*4096; i++ {
		issuer.Sum([]byte("unrelated-" + strconv.Itoa(i)))
	}
	requireComputedContractDigestsRecorded(t)
}

func requireComputedContractDigestsRecorded(t *testing.T) {
	t.Helper()
	contractHash, err := store.ContractHash(contract.Contract{})
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := store.ActiveManifestHash(contract.ActiveManifest{})
	if err != nil {
		t.Fatal(err)
	}
	chosen := "sha256:" + strings.Repeat("bd35", 16)
	cfg := config.Defaults()
	cfg.Internal = nil
	for _, hash := range []string{contractHash, manifestHash, chosen} {
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "digest_" + hash[len(hash)-8:], Regex: strings.TrimPrefix(hash, "sha256:"), Severity: config.SeverityHigh})
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	dir := t.TempDir()
	rec, err := recorder.NewWithScanner(recorder.Config{Enabled: true, Dir: dir, Redact: true}, sc, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	em := NewEmitter(EmitterConfig{Recorder: rec, Signer: NewKeyedSigner(key), Principal: "local", Actor: "agent"})
	d := validDecision()
	d.ContractHash, d.ActiveManifestHash, d.SelectorID, d.ContractGeneration = contractHash, manifestHash, "selector", 1
	for _, hash := range []string{contractHash, manifestHash, chosen} {
		if sc.ScanTextForDLP(context.Background(), hash).Clean {
			t.Fatal("positive control: digest pattern must match")
		}
	}
	for _, field := range []string{"contract", "manifest"} {
		bad := d
		if field == "contract" {
			bad.ContractHash = chosen
		} else {
			bad.ActiveManifestHash = chosen
		}
		if err := em.EmitDurable(bad); !errors.Is(err, receiptcontent.ErrRejected) {
			t.Fatalf("chosen %s digest error = %v, want content rejection", field, err)
		}
		if em.HealthError() != nil {
			t.Fatal("content refusal poisoned emitter")
		}
		if err := em.EmitDurable(d); err != nil {
			t.Fatalf("computed digests refused after content refusal: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := recorder.QuerySession(dir, recorder.DefaultSessionBase, &recorder.QueryFilter{Type: contractreceipt.EvidenceEntryType})
	if err != nil {
		t.Fatal(err)
	}
	entries := result.Entries
	if len(entries) != 2 {
		t.Fatalf("recorded %d entries, want only two clean decisions", len(entries))
	}
	for _, entry := range entries {
		raw, err := json.Marshal(entry.Detail)
		if err != nil {
			t.Fatal(err)
		}
		var rcpt contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(raw, &rcpt); err != nil {
			t.Fatal(err)
		}
		if rcpt.ContractHash != contractHash || rcpt.ActiveManifestHash != manifestHash {
			t.Fatal("computed digests changed in signed output")
		}
		if err := contractreceipt.VerifyWithKey(rcpt, key.Public().(ed25519.PublicKey), NewKeyedSigner(key).KeyID()); err != nil {
			t.Fatal(err)
		}
	}
}
