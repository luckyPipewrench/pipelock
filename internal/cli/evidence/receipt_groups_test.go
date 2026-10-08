// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSingleSessionMaintenanceRefusesGroupEvidence(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "receipt-group-"+strings.Repeat("a", 32)+"-open.json")
	if err := os.WriteFile(artifact, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := runCompact(compactCmd(), compactOptions{
		receiptDir: dir, sessionID: "proxy", publicKey: hex.EncodeToString(pub),
	}); err == nil || !strings.Contains(err.Error(), "signed receipt group") {
		t.Fatalf("compaction accepted a group directory: %v", err)
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Fatalf("compaction changed group artifact: %v", err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Damaged() || report.Conclusive() && len(report.Findings) == 0 {
		t.Fatalf("structural doctor reported a complete group check: %+v", report)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Kind == "group_verification_required" {
			found = true
		}
	}
	if !found {
		t.Fatalf("doctor omitted its group-verification finding: %+v", report)
	}
}

func TestEvidenceDoctorDoesNotCertifyReceiptGroup(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "receipt-group-"+strings.Repeat("a", 32)+"-open.json")
	if err := os.WriteFile(artifact, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := runEvidenceDoctor(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range report.Findings {
		if finding.Kind == "group_verification_required" && report.Damaged() {
			return
		}
	}
	t.Fatalf("doctor certified or omitted a receipt group: %+v", report)
}
