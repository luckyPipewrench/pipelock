//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// setTestFleetLicense issues a fresh Enterprise-tier license (with the fleet
// feature) and installs it via PIPELOCK_LICENSE_KEY +
// PIPELOCK_LICENSE_PUBLIC_KEY env vars for the test's lifetime, so the
// production fleet-license gate in SinkCmd's RunE fires against real signed
// tokens during tests that exercise the running sink. t.Setenv restores
// previous values automatically.
func setTestFleetLicense(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tok, err := license.Issue(license.License{
		ID:        "test-fleet-license",
		Email:     "test@example.com",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Features:  []string{license.FeatureAgents, license.FeatureFleet},
		Tier:      "enterprise",
	}, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	t.Setenv(license.EnvLicenseKey, tok)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, "")
}

// TestSinkCmd_NoFleetLicenseFailsClosed locks in that `pipelock fleet-sink`
// refuses to start when the supplied license does not grant the fleet
// feature, even with otherwise valid arguments.
func TestSinkCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := SinkCmd()
	cmd.SetArgs([]string{"--storage-dir", t.TempDir()})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("SinkCmd without fleet license: want error, got nil")
	}
	if !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("want ErrFleetLicenseRequired, got: %v", err)
	}
}
