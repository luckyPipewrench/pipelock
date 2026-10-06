// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func certificate(t *testing.T, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestValidateCA(t *testing.T) {
	t.Parallel()
	good := certificate(t, nil)
	for _, tt := range []struct {
		name string
		data []byte
		want string
	}{
		{"valid", good, ""},
		{"bundle", append(append([]byte{}, good...), good...), ""},
		{"empty", nil, "no certificates"},
		{"garbage", []byte("garbage"), "expected a PEM"},
		{"trailing garbage", append(append([]byte{}, good...), []byte("garbage")...), "expected a PEM"},
		{"bad PEM", []byte("-----BEGIN CERTIFICATE-----\n??\n-----END CERTIFICATE-----"), "invalid PEM"},
		{"malformed block preceding valid CA", append([]byte("-----BEGIN CERTIFICATE-----\n??\n-----END CERTIFICATE-----\n"), good...), "invalid PEM"},
		{"bad DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), "parse CA"},
		{"key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), "expected a PEM"},
		{"leaf", certificate(t, func(c *x509.Certificate) { c.IsCA = false }), "not a signing CA"},
		{"no cert sign", certificate(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }), "not a signing CA"},
		{"expired", certificate(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }), "expired"},
		{"future", certificate(t, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }), "not yet valid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCA(tt.data, time.Now())
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("err=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestCombinedBundle(t *testing.T) {
	t.Parallel()
	roots, ca := certificate(t, nil), certificate(t, nil)
	for _, system := range [][]byte{roots, bytes.TrimSpace(roots)} {
		bundle, err := CombinedBundle(system, ca)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(bundle, roots) || !bytes.HasSuffix(bundle, ca) {
			t.Fatal("combined bundle did not preserve both root sources")
		}
	}
	if _, err := CombinedBundle([]byte("bad"), ca); err == nil {
		t.Fatal("invalid system roots accepted")
	}
}

func TestWriteBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	data := certificate(t, nil)
	path, err := WriteBundle(dir, data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("bundle=%q err=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("bundle permissions=%o", info.Mode().Perm())
	}
	again, err := WriteBundle(dir, data)
	if err != nil || again != path {
		t.Fatalf("reuse path=%s err=%v, want %s", again, err, path)
	}
	other := certificate(t, nil)
	second, err := WriteBundle(dir, other)
	if err != nil || second == path {
		t.Fatalf("distinct bundle path=%s err=%v", second, err)
	}
	linkParent := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(linkParent, "pipelock")); err != nil {
		t.Logf("symlinks unavailable: %v", err)
	} else if _, err := WriteBundle(linkParent, data); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink cache err=%v", err)
	}
	if _, err := WriteBundle(path, data); err == nil {
		t.Fatal("cache underneath a regular file accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundle(dir, data); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("non-regular bundle path err=%v", err)
	}
}

func TestSystemRoots(t *testing.T) {
	t.Parallel()
	roots, err := SystemRoots()
	if err != nil || !x509.NewCertPool().AppendCertsFromPEM(roots) {
		t.Fatalf("system roots unavailable: %v", err)
	}
}
