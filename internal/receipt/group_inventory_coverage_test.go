// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestReceiptGroupEvidenceDiscoveryDistinguishesLegacyDamageAndGroupGate(t *testing.T) {
	dir := t.TempDir()
	if found, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || found {
		t.Fatalf("empty directory group evidence=%t err=%v", found, err)
	}
	malformed := filepath.Join(dir, "evidence-proxy-0.jsonl")
	if err := os.WriteFile(malformed, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || found {
		t.Fatalf("malformed legacy evidence classified as group: found=%t err=%v", found, err)
	}
	if err := os.WriteFile(malformed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || found {
		t.Fatalf("empty legacy evidence classified as group: found=%t err=%v", found, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReceiptGroupEvidencePresent(dir, 1); found || !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
		t.Fatalf("bounded inventory found=%t err=%v", found, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "receipt-group-present"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReceiptGroupEvidencePresent(dir, 0); err != nil || !found {
		t.Fatalf("group artifact not detected: found=%t err=%v", found, err)
	}

	groupDir, open := newCoverageGroup(t, false)
	paths, err := filepath.Glob(filepath.Join(groupDir, "evidence-"+open.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("group shard files=%v err=%v", paths, err)
	}
	contents, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	gateOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(gateOnly, filepath.Base(paths[0])), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := ReceiptGroupEvidencePresent(gateOnly, 0); err != nil || !found {
		t.Fatalf("orphan group gate not detected: found=%t err=%v", found, err)
	}
}

func TestGroupDirectoryFingerprintRejectsMissingAndRedirectedEvidence(t *testing.T) {
	dir := t.TempDir()
	if _, err := fingerprintGroupDirectory(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing root fingerprint: %v", err)
	}
	if _, err := fingerprintGroupDirectory(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing AEL fingerprint: %v", err)
	}
	ael := filepath.Join(dir, "ael")
	if err := os.Mkdir(ael, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintGroupDirectory(dir); err != nil {
		t.Fatalf("empty AEL inventory: %v", err)
	}
	if err := os.Mkdir(filepath.Join(ael, "invalid-run"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintGroupDirectory(dir); err == nil || !strings.Contains(err.Error(), "invalid native AEL run directory") {
		t.Fatalf("invalid run directory fingerprint: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(ael, "invalid-run")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ael); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ael, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintGroupDirectory(dir); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("file substituted for AEL directory: %v", err)
	}
}

func TestGroupInventoryRejectsUnlistedSignedShard(t *testing.T) {
	dir, open := newCoverageGroup(t, false)
	open.Shards = open.Shards[:1]
	if err := verifyGroupSessionInventory(dir, open); err == nil || !strings.Contains(err.Error(), "unlisted gated session") {
		t.Fatalf("unlisted group shard: %v", err)
	}
}

func TestGroupDirectoryFingerprintRejectsDamagedRunTree(t *testing.T) {
	for _, tc := range []struct {
		name, child string
	}{
		{"run root", ""},
		{"keys", "keys"},
		{"recorders", "recorders"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := newCoverageGroup(t, false)
			ael, err := os.ReadDir(filepath.Join(dir, "ael"))
			if err != nil || len(ael) == 0 {
				t.Fatalf("native runs=%v err=%v", ael, err)
			}
			path := filepath.Join(dir, "ael", ael[0].Name(), tc.child)
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := fingerprintGroupDirectory(dir); err == nil || !strings.Contains(err.Error(), "not a real directory") {
				t.Fatalf("damaged %s fingerprint: %v", tc.name, err)
			}
		})
	}
}
