// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signCRLFile(t *testing.T, path string, priv ed25519.PrivateKey, gen uint64, now time.Time) {
	t.Helper()
	crl, err := SignCRL(CRLPayload{
		Version:    CRLVersion,
		Generation: gen,
		IssuedAt:   now.Add(-time.Hour).Unix(),
		ExpiresAt:  now.Add(24 * time.Hour).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("SignCRL(gen=%d): %v", gen, err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("marshal CRL: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write CRL: %v", err)
	}
}

func TestReadCRLHighWater(t *testing.T) {
	t.Run("absent is first run", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		gen, found, err := ReadCRLHighWater(crlFile)
		if err != nil || found || gen != 0 {
			t.Fatalf("absent high-water = (%d, %v, %v), want (0, false, nil)", gen, found, err)
		}
	})

	t.Run("present value round-trips", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if _, err := AdvanceCRLHighWater(crlFile, 7); err != nil {
			t.Fatalf("AdvanceCRLHighWater: %v", err)
		}
		gen, found, err := ReadCRLHighWater(crlFile)
		if err != nil || !found || gen != 7 {
			t.Fatalf("high-water = (%d, %v, %v), want (7, true, nil)", gen, found, err)
		}
	})

	t.Run("non-regular file fails closed", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		// Make the high-water path a directory rather than a regular file.
		if err := os.MkdirAll(CRLHighWaterPath(crlFile), 0o750); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadCRLHighWater(crlFile); err == nil {
			t.Fatal("non-regular high-water must error, got nil")
		}
	})

	t.Run("oversized file fails closed", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(CRLHighWaterPath(crlFile), make([]byte, crlHighWaterMaxSize+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadCRLHighWater(crlFile); err == nil {
			t.Fatal("oversized high-water must error, got nil")
		}
	})

	t.Run("corrupt json fails closed", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(CRLHighWaterPath(crlFile), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadCRLHighWater(crlFile); err == nil {
			t.Fatal("corrupt high-water must error, got nil")
		}
	})
}

func TestAdvanceCRLHighWater(t *testing.T) {
	t.Run("first write then monotonic advance", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if got, err := AdvanceCRLHighWater(crlFile, 3); err != nil || got != 3 {
			t.Fatalf("first advance = (%d, %v), want (3, nil)", got, err)
		}
		// Higher generation advances.
		if got, err := AdvanceCRLHighWater(crlFile, 9); err != nil || got != 9 {
			t.Fatalf("advance to 9 = (%d, %v), want (9, nil)", got, err)
		}
		// Equal generation is an idempotent no-op that keeps the mark.
		if got, err := AdvanceCRLHighWater(crlFile, 9); err != nil || got != 9 {
			t.Fatalf("re-advance to 9 = (%d, %v), want (9, nil)", got, err)
		}
	})

	t.Run("lower generation is rejected and mark is unchanged", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if _, err := AdvanceCRLHighWater(crlFile, 9); err != nil {
			t.Fatalf("seed advance: %v", err)
		}
		got, err := AdvanceCRLHighWater(crlFile, 4)
		if err == nil || !strings.Contains(err.Error(), "rollback rejected") {
			t.Fatalf("lower advance err = %v, want rollback rejected", err)
		}
		// The returned value is the still-effective high-water, not the rejected one.
		if got != 9 {
			t.Fatalf("rejected advance returned %d, want 9", got)
		}
		// The persisted mark did not regress.
		if gen, _, _ := ReadCRLHighWater(crlFile); gen != 9 {
			t.Fatalf("persisted high-water = %d after rejected rollback, want 9", gen)
		}
	})

	t.Run("existing-but-corrupt mark fails closed instead of resetting", func(t *testing.T) {
		crlFile := filepath.Join(t.TempDir(), "crl.json")
		if err := os.WriteFile(CRLHighWaterPath(crlFile), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := AdvanceCRLHighWater(crlFile, 5); err == nil {
			t.Fatal("advance over corrupt mark must fail closed, got nil")
		}
	})

	t.Run("non-directory parent fails closed", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// crlFile sits under a regular file, so creating the sidecar lock/state
		// directory fails; the advance must surface that rather than proceed.
		crlFile := filepath.Join(blocker, "crl.json")
		if _, err := AdvanceCRLHighWater(crlFile, 1); err == nil {
			t.Fatal("advance under a non-directory parent must fail, got nil")
		}
	})
}

func TestReadCRLHighWaterStatError(t *testing.T) {
	// A path component that is a regular file makes os.Stat fail with a
	// non-ErrNotExist error (ENOTDIR). That must surface fail-closed rather than
	// be mistaken for a genuine first-run absent high-water.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	crlFile := filepath.Join(blocker, "crl.json")
	if _, _, err := ReadCRLHighWater(crlFile); err == nil {
		t.Fatal("stat under a non-directory parent must error, got nil")
	}
}

func TestWriteCRLHighWaterErrors(t *testing.T) {
	t.Run("mkdir failure under non-directory parent", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The sidecar dir cannot be created beneath a regular file.
		if err := writeCRLHighWater(filepath.Join(blocker, "crl.json"), 1); err == nil {
			t.Fatal("write under a non-directory parent must fail, got nil")
		}
	})

	t.Run("atomic write failure in read-only dir", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory write permissions")
		}
		roDir := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(roDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(roDir, 0o500); err != nil { // #nosec G302 -- deliberately read-only dir to exercise the write-failure branch
			t.Fatal(err)
		}
		// Restore write so t.TempDir cleanup can remove the tree.
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o750) }) // #nosec G302 -- restore traversable dir perms for TempDir cleanup
		// MkdirAll no-ops on the existing dir, but the atomic temp-file write
		// cannot create its file in a non-writable directory.
		if err := writeCRLHighWater(filepath.Join(roDir, "crl.json"), 1); err == nil {
			t.Fatal("write into a read-only dir must fail, got nil")
		}
	})
}

func TestAcquireCRLHighWaterLockOpenError(t *testing.T) {
	crlFile := filepath.Join(t.TempDir(), "crl.json")
	lockPath := CRLHighWaterPath(crlFile) + ".lock"
	if err := os.Mkdir(lockPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if unlock, err := acquireCRLHighWaterLock(crlFile); err == nil {
		unlock()
		t.Fatal("lock path that is already a directory must fail, got nil")
	}
}

func TestLoadAndVerifyCRLMonotonic(t *testing.T) {
	pub, priv := testKeyPair(t)
	now := time.Now().UTC()

	t.Run("accepts then rejects a lower-generation swap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "crl.json")
		signCRLFile(t, path, priv, 5, now)
		if _, err := LoadAndVerifyCRLMonotonic(path, pub, now); err != nil {
			t.Fatalf("first load (gen 5): %v", err)
		}
		if gen, _, _ := ReadCRLHighWater(path); gen != 5 {
			t.Fatalf("high-water after gen-5 load = %d, want 5", gen)
		}
		// Swap in an older signed CRL: signature-valid but a revocation rollback.
		signCRLFile(t, path, priv, 3, now)
		_, err := LoadAndVerifyCRLMonotonic(path, pub, now)
		if err == nil || !strings.Contains(err.Error(), "rollback rejected") {
			t.Fatalf("gen-3 swap load err = %v, want rollback rejected", err)
		}
	})

	t.Run("propagates signature verification failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "crl.json")
		signCRLFile(t, path, priv, 1, now)
		wrongPub, _ := testKeyPair(t)
		if _, err := LoadAndVerifyCRLMonotonic(path, wrongPub, now); err == nil {
			t.Fatal("load with wrong verifier key must error, got nil")
		}
	})
}
