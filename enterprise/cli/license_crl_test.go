//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	testRevokedID    = "lic_test_revoked"
	testRevokeReason = "compromised"
)

// writeSignedCRL signs a CRL over the given revoked IDs and writes the wire
// format to a temp file. Uses time.Now()-relative offsets, never a frozen date,
// so the test cannot become a time-bomb.
func writeSignedCRL(t *testing.T, priv ed25519.PrivateKey, ids ...string) string {
	t.Helper()
	now := time.Now()
	revoked := make([]license.RevokedLicense, 0, len(ids))
	for _, id := range ids {
		revoked = append(revoked, license.RevokedLicense{ID: id, Reason: testRevokeReason, RevokedAt: now.Unix()})
	}
	crl, err := license.SignCRL(license.CRLPayload{
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(720 * time.Hour).Unix(),
		Revoked:   revoked,
	}, priv)
	if err != nil {
		t.Fatalf("SignCRL: %v", err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "crl.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	return path
}

// writeExpiredCRLWire hand-builds a past-expiry CRL wire file, signing the
// payload bytes with sign. SignCRL refuses past expiry, so expired fixtures are
// built directly. Callers vary only the signature (junk vs valid) and filename.
func writeExpiredCRLWire(t *testing.T, name string, sign func(payload []byte) string) string {
	t.Helper()
	now := time.Now()
	payload := license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-1440 * time.Hour).Unix(),
		ExpiresAt: now.Add(-720 * time.Hour).Unix(),
		Revoked:   []license.RevokedLicense{{ID: testRevokedID, RevokedAt: now.Add(-1440 * time.Hour).Unix()}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	wire := struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}{
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: sign(raw),
	}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
	return path
}

// writeUnsignedExpiredCRL builds an expired CRL with a junk signature. Inspect
// must decode it (it does not verify); verify must reject it.
func writeUnsignedExpiredCRL(t *testing.T) string {
	t.Helper()
	return writeExpiredCRLWire(t, "expired-crl.json", func([]byte) string {
		return base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	})
}

func runCRLCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := licenseCRLCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *cliutil.ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return -1
}

func TestLicenseCRLInspect(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := writeSignedCRL(t, priv, testRevokedID)

	t.Run("text shows revoked id and unverified warning", func(t *testing.T) {
		out, err := runCRLCmd(t, "inspect", path)
		if err != nil {
			t.Fatalf("inspect: %v", err)
		}
		if !strings.Contains(out, testRevokedID) {
			t.Errorf("output missing revoked id: %s", out)
		}
		if !strings.Contains(out, "NOT verified") {
			t.Errorf("output missing unverified warning: %s", out)
		}
	})

	t.Run("json mode reports signature_verified false", func(t *testing.T) {
		out, err := runCRLCmd(t, "inspect", path, "--json")
		if err != nil {
			t.Fatalf("inspect --json: %v", err)
		}
		var report crlInspectReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("decode json: %v (out=%s)", err, out)
		}
		if report.SignatureVerified {
			t.Error("signature_verified must be false for inspect")
		}
		if len(report.Revoked) != 1 || report.Revoked[0].ID != testRevokedID {
			t.Errorf("unexpected revoked list: %+v", report.Revoked)
		}
	})

	t.Run("expired crl shows expired status", func(t *testing.T) {
		out, err := runCRLCmd(t, "inspect", writeUnsignedExpiredCRL(t))
		if err != nil {
			t.Fatalf("inspect expired: %v", err)
		}
		if !strings.Contains(out, "EXPIRED") {
			t.Errorf("expected EXPIRED status: %s", out)
		}
	})

	t.Run("nonexistent file fails closed", func(t *testing.T) {
		_, err := runCRLCmd(t, "inspect", filepath.Join(t.TempDir(), "nope.json"))
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1, got err=%v", err)
		}
	})

	t.Run("oversized file rejected", func(t *testing.T) {
		big := filepath.Join(t.TempDir(), "big.json")
		if err := os.WriteFile(big, bytes.Repeat([]byte("a"), maxInspectCRLSize+1), 0o600); err != nil {
			t.Fatalf("write big: %v", err)
		}
		_, err := runCRLCmd(t, "inspect", big)
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 for oversized, got err=%v", err)
		}
	})

	t.Run("malformed json fails closed", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write bad: %v", err)
		}
		_, err := runCRLCmd(t, "inspect", bad)
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 for malformed, got err=%v", err)
		}
	})

	t.Run("non-regular file rejected", func(t *testing.T) {
		// A directory is a portable non-regular file; the size guard alone
		// would not catch a device/FIFO, so IsRegular must reject it.
		_, err := runCRLCmd(t, "inspect", t.TempDir())
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 for non-regular file, got err=%v", err)
		}
	})
}

func TestLicenseCRLVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := writeSignedCRL(t, priv, testRevokedID)
	pubHex := hex.EncodeToString(pub)

	t.Run("correct key verifies", func(t *testing.T) {
		out, err := runCRLCmd(t, "verify", path, "--public-key", pubHex)
		if err != nil {
			t.Fatalf("verify: %v (out=%s)", err, out)
		}
		if !strings.Contains(out, "OK") {
			t.Errorf("expected OK: %s", out)
		}
	})

	t.Run("wrong key fails closed", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out, err := runCRLCmd(t, "verify", path, "--public-key", hex.EncodeToString(otherPub))
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 for wrong key, got err=%v out=%s", err, out)
		}
	})

	t.Run("expired but validly-signed crl fails closed", func(t *testing.T) {
		expiredPath := writeValidlySignedExpiredCRL(t, priv)
		out, err := runCRLCmd(t, "verify", expiredPath, "--public-key", pubHex)
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 for expired, got err=%v out=%s", err, out)
		}
	})

	t.Run("missing public key fails closed", func(t *testing.T) {
		// No --public-key, no config, no embedded key in a test build.
		if license.EmbeddedPublicKey() != nil {
			t.Skip("embedded key present in this build")
		}
		_, err := runCRLCmd(t, "verify", path)
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1 when no key available, got err=%v", err)
		}
	})

	t.Run("nonexistent file fails closed", func(t *testing.T) {
		_, err := runCRLCmd(t, "verify", filepath.Join(t.TempDir(), "nope.json"), "--public-key", pubHex)
		if exitCode(t, err) != 1 {
			t.Errorf("want exit 1, got err=%v", err)
		}
	})
}

// writeValidlySignedExpiredCRL builds a CRL with a VALID signature over a
// past-expiry payload, bypassing SignCRL's expiry guard, so verify's expiry
// rejection (not just signature) is exercised end-to-end.
func writeValidlySignedExpiredCRL(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	return writeExpiredCRLWire(t, "signed-expired-crl.json", func(raw []byte) string {
		return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, raw))
	})
}
