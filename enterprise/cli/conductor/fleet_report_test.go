//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestFleetReportCmdRegistered(t *testing.T) {
	cmd := fleetCmd()
	report, _, err := cmd.Find([]string{"report"})
	if err != nil {
		t.Fatalf("Find(report) error = %v", err)
	}
	if report == nil || report.Name() != "report" {
		t.Fatalf("Find(report) = %v", report)
	}
	for _, flag := range []string{"storage-dir", "org-id", "fleet-id", "from", "to", "signing-key", "out", "trusted-audit-key"} {
		if report.Flags().Lookup(flag) == nil {
			t.Fatalf("report flag %q not registered", flag)
		}
	}
}

func TestValidateFleetReportOptions(t *testing.T) {
	opts := fleetReportOptions{
		storageDir:  "/var/lib/pipelock/conductor",
		orgID:       "org-main",
		fleetID:     "prod",
		from:        "2026-06-13T00:00:00Z",
		to:          "2026-06-14T00:00:00Z",
		signingKey:  "/tmp/fleet-report.key",
		out:         "/tmp/fleet-receipt.dsse.json",
		conductorID: "conductor",
	}
	if err := validateFleetReportOptions(opts); err != nil {
		t.Fatalf("validateFleetReportOptions(valid) error = %v", err)
	}
	opts.limit = -1
	if err := validateFleetReportOptions(opts); err == nil || !strings.Contains(err.Error(), "--limit") {
		t.Fatalf("validateFleetReportOptions(negative limit) error = %v, want --limit", err)
	}
	opts.limit = 0
	opts.orgID = ""
	if err := validateFleetReportOptions(opts); err == nil || !strings.Contains(err.Error(), "--org-id") {
		t.Fatalf("validateFleetReportOptions(missing org) error = %v, want --org-id", err)
	}
}

func TestLoadFleetReportSigningKeyPurpose(t *testing.T) {
	dir := t.TempDir()
	_, reportPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(report): %v", err)
	}
	reportPath := writeFleetReportKeyFile(t, dir, "report.key", "report-key-1", signing.PurposeFleetReportSigning, reportPriv)
	keyID, gotPriv, err := loadFleetReportSigningKey(reportPath)
	if err != nil {
		t.Fatalf("loadFleetReportSigningKey() error = %v", err)
	}
	if keyID != "report-key-1" || len(gotPriv) != ed25519.PrivateKeySize {
		t.Fatalf("loadFleetReportSigningKey() = %q len=%d", keyID, len(gotPriv))
	}
	zeroizeKey(gotPriv)

	_, wrongPriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(wrong): %v", err)
	}
	wrongPath := writeFleetReportKeyFile(t, dir, "wrong.key", "policy-key-1", signing.PurposePolicyBundleSigning, wrongPriv)
	if _, _, err := loadFleetReportSigningKey(wrongPath); err == nil || !strings.Contains(err.Error(), "wrong key purpose") {
		t.Fatalf("loadFleetReportSigningKey(wrong purpose) error = %v, want wrong key purpose", err)
	}
}

func TestOpenFleetReportAuditStoreRequiresExistingDB(t *testing.T) {
	cmd := fleetReportCmd()
	_, err := openFleetReportAuditStore(cmd, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "stat Conductor audit store") {
		t.Fatalf("openFleetReportAuditStore(missing) error = %v, want stat error", err)
	}
}

func writeFleetReportKeyFile(t *testing.T, dir, name, keyID string, purpose signing.KeyPurpose, priv ed25519.PrivateKey) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	data := `{
  "schema_version": 1,
  "purpose": "` + purpose.String() + `",
  "key_id": "` + keyID + `",
  "public": "` + hex.EncodeToString(pub) + `",
  "private": "` + hex.EncodeToString(priv) + `",
  "created_at": "2026-06-13T00:00:00Z"
}
`
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	return path
}
