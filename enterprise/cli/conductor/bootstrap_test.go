//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// privateFleetDir returns a fleet directory whose ancestors are not
// world-writable (the conductor config validator rejects world-writable
// parents, and shared /tmp trips that check).
func privateFleetDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp(".", ".bootstrap-cli-*")
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

// setFleetLicenseEnv issues a fleet-flagged license with a throwaway key and
// installs it in the environment so VerifyFleet (which has no build-embedded
// key in tests) accepts it.
func setFleetLicenseEnv(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	token, err := license.Issue(license.License{
		ID:        "lic_test_operator",
		Email:     "operator@example.com",
		Features:  []string{license.FeatureFleet},
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	t.Setenv(license.EnvLicenseKey, token)
	t.Setenv(license.EnvLicensePublicKey, hex.EncodeToString(pub))
	t.Setenv(license.EnvLicenseCRLFile, "")
}

func TestBootstrapCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{"bootstrap", "--dir", privateFleetDir(t)})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("bootstrap without fleet license: err = %v, want ErrFleetLicenseRequired", err)
	}
}

func TestBootstrapCmd_StandsUpFleet(t *testing.T) {
	setFleetLicenseEnv(t)
	dir := privateFleetDir(t)
	var out bytes.Buffer
	cmd := Cmd()
	cmd.SetArgs([]string{"bootstrap", "--dir", dir, "--fleet", "demo", "--trust-domain", "demo.example", "--conductor-id", "conductor-demo"})
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"verifying fleet stood up",
		"verified OFFLINE with existing verifier   true",
		"DEPLOYMENT-ENFORCED",
		"fleets/demo/",
		"--follower-trust-domain demo.example",
		"--conductor-id conductor-demo",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bootstrap output missing %q\n--- output ---\n%s", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-batch.json")); err != nil {
		t.Fatalf("expected audit-batch.json: %v", err)
	}
}

func TestBootstrapCmd_RequiresDir(t *testing.T) {
	setFleetLicenseEnv(t)
	cmd := Cmd()
	cmd.SetArgs([]string{"bootstrap"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("bootstrap without --dir: want error, got nil")
	}
}
