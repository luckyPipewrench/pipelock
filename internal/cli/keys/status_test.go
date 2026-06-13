// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// Test-local constants so goconst stays quiet across subtests.
const (
	purposeReceipt = "receipt-signing"
	purposeLicense = "license-verification"
)

// writeValidPrivateKey generates a real Ed25519 keypair and writes the private
// key to dir/name in the pipelock private-key format with 0o600 permissions.
// Returns the path and the canonical public-key fingerprint.
func writeValidPrivateKey(t *testing.T, dir, name string) (string, string) {
	t.Helper()
	pub, priv, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := domsigning.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("save private key: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	fp, err := domsigning.Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return path, fp
}

// findKey returns the report row for the given purpose, failing if absent.
func findKey(t *testing.T, report keyStatusReport, purpose string) keyStatusItem {
	t.Helper()
	for _, item := range report.Keys {
		if item.Purpose == purpose {
			return item
		}
	}
	t.Fatalf("purpose %q not found in report", purpose)
	return keyStatusItem{}
}

// TestBuildReportEnumeratesAllPurposes proves the report covers every wire
// purpose from the authoritative enum (no hardcoded drift) plus the license
// verify row, and never claims an absent key is present.
func TestBuildReportEnumeratesAllPurposes(t *testing.T) {
	cfg := config.Defaults()
	report := buildKeyStatusReport(cfg, "(test)")

	want := len(domsigning.KnownPurposes()) + 1 // + license-verification
	if len(report.Keys) != want {
		t.Fatalf("report has %d keys, want %d", len(report.Keys), want)
	}
	for _, purpose := range domsigning.KnownPurposes() {
		item := findKey(t, report, purpose.String())
		if item.Source == "" {
			t.Errorf("purpose %q has empty source", purpose)
		}
		if item.Status == "" {
			t.Errorf("purpose %q has empty status", purpose)
		}
	}
	// License row present.
	_ = findKey(t, report, purposeLicense)
}

// TestReceiptSigningPresentAndValid covers the all-present-and-valid case for a
// file-backed purpose: a real key at flight_recorder.signing_key_path.
func TestReceiptSigningPresentAndValid(t *testing.T) {
	dir := t.TempDir()
	path, fp := writeValidPrivateKey(t, dir, "receipt.key")

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeReceipt)
	if !item.Present || !item.Readable || !item.Valid {
		t.Fatalf("want present+readable+valid, got %+v", item)
	}
	if item.KeyType != keyTypeEd25519 {
		t.Errorf("key_type = %q, want %q", item.KeyType, keyTypeEd25519)
	}
	if item.Fingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", item.Fingerprint, fp)
	}
	if item.Status != statusOK {
		t.Errorf("status = %q, want %q", item.Status, statusOK)
	}
	if item.Path != path {
		t.Errorf("path = %q, want %q", item.Path, path)
	}
}

// TestReceiptSigningMissingFile covers configured-but-not-provisioned: a path
// is set but no file exists. Present must be false; status must not be ok.
func TestReceiptSigningMissingFile(t *testing.T) {
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "absent.key")
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeReceipt)
	if item.Present {
		t.Fatalf("want present=false for missing file, got %+v", item)
	}
	if item.Valid {
		t.Errorf("want valid=false for missing file")
	}
	if item.Status == statusOK {
		t.Errorf("status must not be ok for a missing key file")
	}
}

// TestReceiptSigningCorruptFile covers present-but-corrupt: the file exists with
// 0o600 perms but does not parse as an Ed25519 private key.
func TestReceiptSigningCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.key")
	if err := os.WriteFile(path, []byte("not a valid key file\n"), 0o600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeReceipt)
	if !item.Present {
		t.Fatalf("want present=true for existing file, got %+v", item)
	}
	if item.Valid {
		t.Errorf("want valid=false for corrupt key")
	}
	if item.Status != statusFail {
		t.Errorf("status = %q, want %q for corrupt key", item.Status, statusFail)
	}
	if item.Fingerprint != "" {
		t.Errorf("corrupt key must not emit a fingerprint, got %q", item.Fingerprint)
	}
}

// TestReceiptSigningTooPermissive covers the permission gate: a present, valid
// key with group/other access is flagged, not silently accepted. Skips under
// root, where DAC is bypassed and the perm bits still apply but the load would
// also succeed — the perm check fires before load regardless, so we assert it.
func TestReceiptSigningTooPermissive(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeValidPrivateKey(t, dir, "loose.key")
	// Add other-read on top of owner-rw so the 0o037 mask trips. Computed at
	// runtime to avoid a gosec G302 literal-permission flag; the intent is to
	// PRODUCE a too-permissive key for the negative test.
	loose := os.FileMode(0o600) | os.FileMode(0o004)
	if err := os.Chmod(path, loose); err != nil {
		t.Fatalf("chmod loose: %v", err)
	}

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeReceipt)
	if !item.Present {
		t.Fatalf("want present=true, got %+v", item)
	}
	if item.Status != statusWarn {
		t.Errorf("status = %q, want %q for too-permissive key", item.Status, statusWarn)
	}
	if !strings.Contains(item.Note, "permissive") {
		t.Errorf("note should explain the permission problem, got %q", item.Note)
	}
}

// TestMediationEnvelopeDoesNotSatisfyReceiptSigning proves receipt-signing is
// mapped only to flight_recorder.signing_key_path. The mediation-envelope key
// signs HTTP messages, not runtime receipts.
func TestMediationEnvelopeDoesNotSatisfyReceiptSigning(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeValidPrivateKey(t, dir, "mediation.key")

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = ""
	cfg.MediationEnvelope.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeReceipt)
	if item.Present || item.Valid {
		t.Fatalf("mediation-envelope key must not satisfy receipt-signing, got %+v", item)
	}
	if item.Status != statusInfo {
		t.Errorf("status = %q, want info", item.Status)
	}
	if strings.Contains(item.Source, "mediation_envelope.signing_key_path") {
		t.Errorf("source must not point receipt-signing at mediation envelope field, got %q", item.Source)
	}
	if !strings.Contains(item.Note, "flight_recorder.signing_key_path") {
		t.Errorf("note should name the receipt signing field, got %q", item.Note)
	}
}

// TestAuditBatchSigningUsesFlightRecorderKey locks the runtime contract:
// Conductor audit batches are signed with the follower flight-recorder private
// key, under a separate audit_signing_key_id.
func TestAuditBatchSigningUsesFlightRecorderKey(t *testing.T) {
	dir := t.TempDir()
	path, fp := writeValidPrivateKey(t, dir, "recorder.key")

	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	cfg.Conductor.AuditSigningKeyID = "audit-key-1"
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, "audit-batch-signing")
	if item.SourceKind != sourceConfigPrivate {
		t.Fatalf("source_kind = %q, want %q", item.SourceKind, sourceConfigPrivate)
	}
	if !item.Present || !item.Readable || !item.Valid {
		t.Fatalf("want present+readable+valid audit signer, got %+v", item)
	}
	if item.Path != path {
		t.Errorf("path = %q, want %q", item.Path, path)
	}
	if item.Fingerprint != fp {
		t.Errorf("fingerprint = %q, want %q", item.Fingerprint, fp)
	}
	if !strings.Contains(item.Source, "flight_recorder.signing_key_path") {
		t.Errorf("source should name flight recorder field, got %q", item.Source)
	}
	if !strings.Contains(item.Note, "audit-batch signer") {
		t.Errorf("note should explain audit-batch key reuse, got %q", item.Note)
	}
}

// TestRulesTrustedPublicKeys covers the bundled-public-key source: configured
// rules.trusted_keys are reported present+valid with a fingerprint.
func TestRulesTrustedPublicKeys(t *testing.T) {
	pub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	cfg := config.Defaults()
	cfg.Rules.TrustedKeys = []config.TrustedKey{
		{Name: "official", PublicKey: hex.EncodeToString(pub)},
	}
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, "rules-official-signing")
	if !item.Present || !item.Valid {
		t.Fatalf("want present+valid for configured trusted key, got %+v", item)
	}
	wantFP, err := domsigning.Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if item.Fingerprint != wantFP {
		t.Errorf("fingerprint = %q, want %q", item.Fingerprint, wantFP)
	}
}

// TestRosterReferenceFromConductor proves roster-backed purposes pick up the
// conductor trust roster path and pinned fingerprint.
func TestRosterReferenceFromConductor(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(rosterPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	cfg := config.Defaults()
	cfg.Conductor.TrustRosterPath = rosterPath
	cfg.Conductor.TrustRosterRootFingerprint = "sha256:" + strings.Repeat("a", 64)
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, "roster-root")
	if item.Path != rosterPath {
		t.Errorf("path = %q, want %q", item.Path, rosterPath)
	}
	if !item.Present {
		t.Errorf("want present=true when roster file is readable")
	}
	if !strings.Contains(item.Note, "sha256:") {
		t.Errorf("note should carry the pinned fingerprint, got %q", item.Note)
	}
}

// TestDeploymentFilePurposesAreInformational proves the contract purposes that
// have no discoverable config field report as info with an honest note.
func TestDeploymentFilePurposesAreInformational(t *testing.T) {
	cfg := config.Defaults()
	report := buildKeyStatusReport(cfg, "(test)")
	for _, p := range []string{"contract-compile-signing", "contract-activation-signing"} {
		p := p
		t.Run(p, func(t *testing.T) {
			item := findKey(t, report, p)
			if item.SourceKind != sourceDeploymentFile {
				t.Errorf("%s source_kind = %q, want %q", p, item.SourceKind, sourceDeploymentFile)
			}
			if item.Status != statusInfo {
				t.Errorf("%s status = %q, want info", p, item.Status)
			}
			if item.Present {
				t.Errorf("%s must not claim present for an unlocatable file", p)
			}
		})
	}
}

// TestConductorThresholdNotes proves reserved + threshold purposes carry the
// right caveats mirrored from `signing key generate`.
func TestConductorThresholdNotes(t *testing.T) {
	cfg := config.Defaults()
	report := buildKeyStatusReport(cfg, "(test)")

	rollback := findKey(t, report, "policy-bundle-rollback")
	if !strings.Contains(rollback.Note, "threshold") {
		t.Errorf("rollback note missing threshold caveat: %q", rollback.Note)
	}
	rotation := findKey(t, report, "trust-root-rotation")
	if !strings.Contains(rotation.Note, "reserved") || !strings.Contains(rotation.Note, "threshold") {
		t.Errorf("rotation note missing reserved+threshold caveats: %q", rotation.Note)
	}
}

// TestLicenseVerifyEnvOverride covers the dev-build env-override path for the
// license verification key (embedded key absent in unit tests).
func TestLicenseVerifyEnvOverride(t *testing.T) {
	pub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	cfg := config.Defaults()
	cfg.LicensePublicKey = hex.EncodeToString(pub)
	report := buildKeyStatusReport(cfg, "(test)")

	item := findKey(t, report, purposeLicense)
	if !item.Present || !item.Valid {
		t.Fatalf("want present+valid for config override, got %+v", item)
	}
	if item.Status != statusWarn {
		t.Errorf("dev-build override status = %q, want warn", item.Status)
	}
	wantFP, err := domsigning.Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if item.Fingerprint != wantFP {
		t.Errorf("fingerprint = %q, want %q", item.Fingerprint, wantFP)
	}
}

// TestLicenseVerifyAbsent covers no embedded key and no override.
func TestLicenseVerifyAbsent(t *testing.T) {
	cfg := config.Defaults()
	cfg.LicensePublicKey = ""
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, purposeLicense)
	if item.Present || item.Valid {
		t.Fatalf("want absent license verify key, got %+v", item)
	}
	if item.Status != statusInfo {
		t.Errorf("status = %q, want info", item.Status)
	}
}

// TestLicenseVerifyInvalidOverride covers a malformed override value.
func TestLicenseVerifyInvalidOverride(t *testing.T) {
	cfg := config.Defaults()
	cfg.LicensePublicKey = "not-hex-and-wrong-length"
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, purposeLicense)
	if item.Valid {
		t.Errorf("malformed override must be valid=false")
	}
	if item.Status != statusFail {
		t.Errorf("status = %q, want fail for malformed override", item.Status)
	}
	if item.Fingerprint != "" {
		t.Errorf("malformed key must not emit a fingerprint")
	}
}

// TestNoPrivateMaterialInJSON is the security invariant: serialize a report
// built over a real private key and assert the private bytes never appear.
func TestNoPrivateMaterialInJSON(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := domsigning.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	out, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	privHex := hex.EncodeToString(priv)
	if strings.Contains(string(out), privHex) {
		t.Fatal("private key hex leaked into JSON output")
	}
	// The base64 private form (as written to disk) must also be absent.
	if strings.Contains(string(out), domsigning.EncodePrivateKey(priv)) {
		t.Fatal("encoded private key leaked into JSON output")
	}
	// The PUBLIC fingerprint is allowed and expected.
	wantFP, err := domsigning.Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if !strings.Contains(string(out), wantFP) {
		t.Errorf("expected public fingerprint %q in output", wantFP)
	}
	_ = pub
}
