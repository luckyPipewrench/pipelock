//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privateFleetDir returns an absolute fleet directory whose ancestors are not
// world-writable. The conductor config validator rejects world-writable
// parents, and the shared /tmp (mode 1777) trips that check, so fleet material
// in tests lives in a dot-prefixed dir under the package directory (the same
// convention internal/config and internal/cli/runtime conductor tests use).
func privateFleetDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp(".", ".bootstrap-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	abs, err := filepath.Abs(filepath.Join(base, "fleet"))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return abs
}

// TestRun_StandsUpVerifyingFleet is the done-state proof: from a clean
// directory, Run mints the material, stands up one Conductor and one follower
// in-process, ingests a follower-signed audit batch over mTLS, queries it back,
// and verifies it offline with the existing verifier.
func TestRun_StandsUpVerifyingFleet(t *testing.T) {
	dir := privateFleetDir(t)
	var out bytes.Buffer
	res, err := Run(context.Background(), Options{Dir: dir, Out: &out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reused {
		t.Fatal("fresh bootstrap reported reused material")
	}
	if res.Proof == nil {
		t.Fatal("Run produced no proof")
	}
	p := res.Proof
	if p.IngestStatus != 202 {
		t.Fatalf("ingest status = %d, want 202", p.IngestStatus)
	}
	if !p.QueriedBack {
		t.Fatal("proof did not query the batch back through the auditor API")
	}
	if !p.OfflineVerified {
		t.Fatal("proof did not verify the audit batch offline")
	}
	if p.BatchID == "" || p.EnvelopeHash == "" {
		t.Fatalf("proof missing batch identifiers: %+v", p)
	}
	if p.EventCount == 0 || p.SeqEnd < p.SeqStart {
		t.Fatalf("proof has implausible sequence/count: %+v", p)
	}
	if res.RootFingerprint == "" || !strings.HasPrefix(res.RootFingerprint, "sha256:") {
		t.Fatalf("root fingerprint = %q, want sha256: prefix", res.RootFingerprint)
	}
	if len(res.LicensePubHex) != 64 {
		t.Fatalf("license pub hex len = %d, want 64", len(res.LicensePubHex))
	}

	// Every material file exists with locked-down permissions.
	wantFiles := []string{
		res.Layout.CACertPath, res.Layout.CAKeyPath,
		res.Layout.ConductorServerCertPath, res.Layout.ConductorServerKeyPath,
		res.Layout.FollowerClientCertPath, res.Layout.FollowerClientKeyPath,
		res.Layout.FollowerAuditKeyPath, res.Layout.FollowerConfigPath,
		res.Layout.TrustRosterPath, res.Layout.LicenseTokenPath,
		res.Layout.PublisherTokenPath, res.Layout.AuditorTokenPath, res.Layout.AdminTokenPath,
		res.Layout.AuditBatchPath, res.Layout.ManifestPath,
	}
	for _, f := range wantFiles {
		info, statErr := os.Stat(f)
		if statErr != nil {
			t.Fatalf("expected material file %s: %v", f, statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %s has perm %04o, want 0600", f, perm)
		}
	}

	// Quickstart output makes the honest claim and never prints a token value.
	q := out.String()
	for _, want := range []string{
		"verifying fleet stood up", "DEPLOYMENT-ENFORCED", "pipelock conductor serve", "pipelock run -c",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("quickstart output missing %q", want)
		}
	}
}

// TestRun_IdempotentReuse proves a second run reuses existing material rather
// than double-issuing keys, and still re-proves the round-trip.
func TestRun_IdempotentReuse(t *testing.T) {
	dir := privateFleetDir(t)
	first, err := Run(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	caBefore, err := os.ReadFile(first.Layout.CACertPath)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Run(context.Background(), Options{Dir: dir})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !second.Reused {
		t.Fatal("second Run did not reuse existing material")
	}
	if second.Proof == nil || !second.Proof.OfflineVerified {
		t.Fatal("reused run failed to re-prove the round-trip")
	}
	caAfter, err := os.ReadFile(first.Layout.CACertPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(caBefore, caAfter) {
		t.Fatal("idempotent re-run re-issued the CA (double-issue)")
	}
}

// TestRun_SkipProofGeneratesMaterialOnly covers the material-only path.
func TestRun_SkipProofGeneratesMaterialOnly(t *testing.T) {
	dir := privateFleetDir(t)
	res, err := Run(context.Background(), Options{Dir: dir, SkipProof: true})
	if err != nil {
		t.Fatalf("Run(SkipProof): %v", err)
	}
	if res.Proof != nil {
		t.Fatal("SkipProof should produce no proof")
	}
	if _, statErr := os.Stat(res.Layout.AuditBatchPath); statErr == nil {
		t.Fatal("SkipProof should not write an audit batch")
	}
	if _, statErr := os.Stat(res.Layout.ManifestPath); statErr != nil {
		t.Fatalf("SkipProof should still write the manifest: %v", statErr)
	}
}
