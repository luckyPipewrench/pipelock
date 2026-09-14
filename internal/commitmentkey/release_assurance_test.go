// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	cryptorand "crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type entropyFailureReader struct {
	failAfter int
	reads     int
}

func (r *entropyFailureReader) Read(p []byte) (int, error) {
	if r.reads >= r.failAfter {
		return 0, errors.New("entropy source unavailable")
	}
	r.reads++
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

func TestReleaseAssuranceEntropyFailurePreservesLifecycleState(t *testing.T) {
	t.Run("initialization does not create a keyring", func(t *testing.T) {
		originalReader := cryptorand.Reader
		cryptorand.Reader = &entropyFailureReader{}
		t.Cleanup(func() { cryptorand.Reader = originalReader })

		path := filepath.Join(t.TempDir(), "keyring.json")
		if _, err := Initialize(path, time.Unix(1_700_000_000, 0)); err == nil || !strings.Contains(err.Error(), "generate commitment key") {
			t.Fatalf("Initialize entropy failure = %v, want key-generation failure", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed Initialize created keyring: %v", err)
		}
	})

	t.Run("initialization refuses an overlong destination name", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, strings.Repeat("k", 256))
		if _, err := Initialize(path, time.Unix(1_700_000_000, 0)); err == nil {
			t.Fatal("Initialize accepted an overlong destination name")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir after rejected Initialize: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("failed Initialize left %d file(s) behind", len(entries))
		}
	})

	t.Run("rotation leaves committed keyring usable", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keyring.json")
		keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		receipt := commitTestReceipt(t, keyring, "before entropy failure")
		before, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile before Rotate: %v", err)
		}

		originalReader := cryptorand.Reader
		cryptorand.Reader = &entropyFailureReader{}
		t.Cleanup(func() { cryptorand.Reader = originalReader })
		if _, _, err := Rotate(path, time.Unix(1_700_000_100, 0)); err == nil || !strings.Contains(err.Error(), "generate commitment key") {
			t.Fatalf("Rotate entropy failure = %v, want key-generation failure", err)
		}

		after, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile after Rotate: %v", err)
		}
		if string(after) != string(before) {
			t.Fatal("failed Rotate changed the committed keyring")
		}
		restarted, err := Load(path)
		if err != nil {
			t.Fatalf("Load preserved keyring: %v", err)
		}
		openTestReceipt(t, restarted, receipt)
	})

	t.Run("key identifier entropy failure is reported", func(t *testing.T) {
		originalReader := cryptorand.Reader
		cryptorand.Reader = &entropyFailureReader{failAfter: 1}
		t.Cleanup(func() { cryptorand.Reader = originalReader })

		if _, err := newEntry(1, time.Unix(1_700_000_000, 0)); err == nil || !strings.Contains(err.Error(), "generate commitment key ID") {
			t.Fatalf("newEntry identifier entropy failure = %v, want key-ID generation failure", err)
		}
	})
}

func TestReleaseAssuranceInvalidTimestampCannotBeCommitted(t *testing.T) {
	t.Run("initialization rejects an unrepresentable clock value", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keyring.json")
		if _, err := Initialize(path, time.Date(10_000, time.January, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "marshal canonical commitment keyring content") {
			t.Fatalf("Initialize invalid timestamp = %v, want canonical-content refusal", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid clock value created keyring: %v", err)
		}
	})

	path := filepath.Join(t.TempDir(), "keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	invalid := cloneKeyring(keyring)
	invalid.Keys[0].CreatedAt = time.Date(10_000, time.January, 1, 0, 0, 0, 0, time.UTC)
	invalid.ContentCheck = "present"

	if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "marshal canonical commitment keyring content") {
		t.Fatalf("Validate invalid timestamp = %v, want canonical-content refusal", err)
	}
	if _, err := marshal(invalid); err == nil || !strings.Contains(err.Error(), "marshal canonical commitment keyring content") {
		t.Fatalf("marshal invalid timestamp = %v, want canonical-content refusal", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load original keyring: %v", err)
	}
	if loaded.Keys[0].CreatedAt.Year() == invalid.Keys[0].CreatedAt.Year() {
		t.Fatal("invalid in-memory timestamp affected persisted keyring")
	}
}

func TestReleaseAssuranceFailedWritesPreserveCommittedKeyrings(t *testing.T) {
	t.Run("rotation rejects a substituted destination", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows symlink privileges and semantics differ from Unix O_NOFOLLOW handling")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "keyring.json")
		keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
		if err != nil {
			t.Fatalf("Initialize: %v", err)
		}
		receipt := commitTestReceipt(t, keyring, "before rejected write")
		before, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile before rotate: %v", err)
		}
		link := filepath.Join(dir, "substituted.json")
		if err := os.Symlink(path, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}

		snapshot := cloneKeyring(keyring)
		if _, err := keyring.rotate(link, time.Unix(1_700_000_100, 0)); !errors.Is(err, ErrSymlink) {
			t.Fatalf("rotate through substituted destination = %v, want ErrSymlink", err)
		}
		if !reflect.DeepEqual(keyring, snapshot) {
			t.Fatal("rejected rotation changed the receiver")
		}
		after, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("ReadFile after rotate: %v", err)
		}
		if string(after) != string(before) {
			t.Fatal("rejected rotation changed the committed keyring")
		}
		restarted, err := Load(path)
		if err != nil {
			t.Fatalf("Load preserved keyring: %v", err)
		}
		openTestReceipt(t, restarted, receipt)
	})
}

func TestReleaseAssuranceRetirementPreservesReceiverUntilSaved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink privileges and semantics differ from Unix O_NOFOLLOW handling")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	old, err := keyring.Active()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.rotate(path, time.Unix(1_700_000_100, 0)); err != nil {
		t.Fatal(err)
	}
	snapshot := cloneKeyring(keyring)
	link := filepath.Join(dir, "substituted.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := keyring.retire(link, old.KeyID, old.Epoch, true); !errors.Is(err, ErrSymlink) {
		t.Fatalf("retire = %v, want ErrSymlink", err)
	}
	if !reflect.DeepEqual(keyring, snapshot) {
		t.Fatal("failed retirement changed the receiver")
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded, snapshot) {
		t.Fatal("failed retirement changed the persisted keyring")
	}
	if err := keyring.retire(path, old.KeyID, old.Epoch, true); err != nil {
		t.Fatalf("valid retirement: %v", err)
	}
	if _, err := keyring.Open(old.KeyID, old.Epoch); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("retired key remains in receiver: %v", err)
	}
	reloaded, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.Open(old.KeyID, old.Epoch); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("retired key remains persisted: %v", err)
	}
}

func TestReleaseAssuranceRotationEntropyFailurePreservesReceiver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	keyring, err := Initialize(path, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := cloneKeyring(keyring)
	originalReader := cryptorand.Reader
	cryptorand.Reader = &entropyFailureReader{}
	t.Cleanup(func() { cryptorand.Reader = originalReader })
	if _, err := keyring.rotate(path, time.Unix(1_700_000_100, 0)); err == nil {
		t.Fatal("rotation accepted unavailable entropy")
	}
	if !reflect.DeepEqual(keyring, snapshot) {
		t.Fatal("failed key generation changed the receiver")
	}
}
