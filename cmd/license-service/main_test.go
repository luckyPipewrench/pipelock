//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/rs/zerolog"
)

func writeServiceTestIntermediate(t *testing.T, intermediatePub ed25519.PublicKey) string {
	t.Helper()
	_, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	now := time.Now().UTC()
	im, err := license.SignIntermediate(license.IntermediatePayload{
		Serial:    "im_cmd_test",
		Purpose:   license.PurposeLicenseSigning,
		Algorithm: license.AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intermediatePub),
		NotBefore: now.Add(-time.Minute).Unix(),
		NotAfter:  now.Add(time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	data, err := json.Marshal(im)
	if err != nil {
		t.Fatalf("Marshal intermediate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "intermediate.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write intermediate: %v", err)
	}
	return path
}

func writeServiceTestKey(t *testing.T, name string) (ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".key")
	if err := signing.SavePrivateKey(priv, path); err != nil {
		t.Fatalf("SavePrivateKey(%s): %v", name, err)
	}
	return pub, path
}

func setServiceRunEnv(t *testing.T, keyPath, certPath string) {
	t.Helper()
	t.Setenv("POLAR_WEBHOOK_SECRET", "whsec_"+"dGVzdA==")
	t.Setenv("POLAR_API_TOKEN", "polar_"+"test")
	t.Setenv("PIPELOCK_LICENSE_KEY_PATH", keyPath)
	t.Setenv("PIPELOCK_LICENSE_INTERMEDIATE_FILE", certPath)
	t.Setenv("RESEND_API_KEY", "re_"+"test")
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "missing-parent", "licenses.db"))
}

func TestRun_LoadsIntermediateAndCRLKeysBeforeDatabaseOpen(t *testing.T) {
	pub, keyPath := writeServiceTestKey(t, "token")
	certPath := writeServiceTestIntermediate(t, pub)
	_, crlKeyPath := writeServiceTestKey(t, "crl")
	setServiceRunEnv(t, keyPath, certPath)
	t.Setenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH", crlKeyPath)

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "open database") {
		t.Fatalf("run() error = %v, want database open failure after key/cert loading", err)
	}
}

func TestRun_LoadIntermediateFailure(t *testing.T) {
	_, keyPath := writeServiceTestKey(t, "token")
	setServiceRunEnv(t, keyPath, filepath.Join(t.TempDir(), "missing-intermediate.json"))

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "load intermediate certificate") {
		t.Fatalf("run() error = %v, want intermediate load failure", err)
	}
}

func TestRun_LoadCRLSigningKeyFailure(t *testing.T) {
	pub, keyPath := writeServiceTestKey(t, "token")
	certPath := writeServiceTestIntermediate(t, pub)
	setServiceRunEnv(t, keyPath, certPath)
	t.Setenv("PIPELOCK_LICENSE_CRL_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "missing-crl.key"))

	err := run(zerolog.New(io.Discard))
	if err == nil || !strings.Contains(err.Error(), "load CRL signing key") {
		t.Fatalf("run() error = %v, want CRL key load failure", err)
	}
}
