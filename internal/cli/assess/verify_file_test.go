// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingAssessReader struct{}

func (failingAssessReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestAssessVerifyStreamBoundaries(t *testing.T) {
	for name, read := range map[string]func(io.Reader) error{
		"read": func(r io.Reader) error { _, err := readAssessVerifyStream(r); return err },
		"hash": func(r io.Reader) error { _, err := hashAssessVerifyStream(r); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := read(failingAssessReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("read error: %v", err)
			}
			if err := read(io.LimitReader(strings.NewReader(strings.Repeat("x", 8192)), 3)); err != nil {
				t.Fatalf("short read: %v", err)
			}
			if err := read(strings.NewReader(strings.Repeat("x", int(maxAssessVerifyFileBytes)+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("oversized stream: %v", err)
			}
		})
	}
}

func TestAssessVerifyFileBoundaries(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if _, err := openAssessVerifyFile(missing); !os.IsNotExist(err) {
		t.Fatalf("missing input: %v", err)
	}
	if _, err := readAssessVerifyFile(missing); !os.IsNotExist(err) {
		t.Fatalf("missing read: %v", err)
	}
	if _, err := hashAssessVerifyFile(missing); !os.IsNotExist(err) {
		t.Fatalf("missing hash: %v", err)
	}
	if _, err := loadAssessVerifySignature(missing); !os.IsNotExist(err) {
		t.Fatalf("missing signature: %v", err)
	}
	if _, err := openAssessVerifyFile(dir); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory input: %v", err)
	}

	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(path, link); err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrInvalid) || errors.Is(err, errors.ErrUnsupported) {
				t.Skipf("host cannot create symlinks: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := openAssessVerifyFile(link); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink input: %v", err)
		}
	})
	got, err := readAssessVerifyFile(path)
	if err != nil || string(got) != "abc" {
		t.Fatalf("short read: %q, %v", got, err)
	}
	wantHash := sha256.Sum256([]byte("abc"))
	hash, err := hashAssessVerifyFile(path)
	if err != nil || hash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("short hash: %q, %v", hash, err)
	}

	if err := os.Truncate(path, maxAssessVerifyFileBytes+1); err != nil {
		t.Fatal(err)
	}
	for name, read := range map[string]func(string) error{
		"open": func(p string) error {
			f, err := openAssessVerifyFile(p)
			if err == nil {
				_ = f.Close()
			}
			return err
		},
		"read": func(p string) error { _, err := readAssessVerifyFile(p); return err },
		"hash": func(p string) error { _, err := hashAssessVerifyFile(p); return err },
	} {
		t.Run(name+" oversized", func(t *testing.T) {
			if err := read(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("oversized input: %v", err)
			}
		})
	}
}

func TestAssessVerifySignatureEncoding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signature")
	for _, tc := range []struct {
		name, data, want string
	}{
		{"invalid base64", "!", "decoding signature"},
		{"short signature", base64.StdEncoding.EncodeToString([]byte("short")), "invalid signature length"},
		{"valid signature", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			sig, err := loadAssessVerifySignature(path)
			if tc.want == "" {
				if err != nil || len(sig) != ed25519.SignatureSize {
					t.Fatalf("signature: %d bytes, %v", len(sig), err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("signature error: %v", err)
			}
		})
	}
}
