package hermes

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func lockTestEnvironment(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv("LOCALAPPDATA", filepath.Join(root, "cache"))
	old := hermesLockTimeout
	hermesLockTimeout = 40 * time.Millisecond
	t.Cleanup(func() { hermesLockTimeout = old })
	return root
}

func TestHermesCommandLockResourcesAndContention(t *testing.T) {
	root := lockTestEnvironment(t)
	configA := filepath.Join(root, "a", "config.yaml")
	configB := filepath.Join(root, "b", "config.yaml")
	homeA := filepath.Join(root, "home-a")
	homeB := filepath.Join(root, "home-b")
	for _, tc := range []struct{ name, heldConfig, heldHome, secondConfig, secondHome string }{
		{"same home", configA, homeA, configB, homeA},
		{"same config", configA, homeA, configA, homeB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- withHermesCommandLock(tc.heldConfig, tc.heldHome, func() error { close(entered); <-release; return nil })
			}()
			<-entered
			called := false
			err := withHermesCommandLock(tc.secondConfig, tc.secondHome, func() error { called = true; return nil })
			if err == nil || called || !strings.Contains(err.Error(), "another pipelock hermes install or rollback") || !strings.Contains(err.Error(), ".lock") {
				t.Errorf("contention err=%v called=%v", err, called)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := withHermesCommandLock(tc.secondConfig, tc.secondHome, func() error { called = true; return nil }); err != nil || !called {
				t.Fatalf("after release err=%v called=%v", err, called)
			}
		})
	}
}

func TestHermesCommandLockOrder(t *testing.T) {
	root := lockTestEnvironment(t)
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		wg.Add(1)
		go func(config, home string) {
			defer wg.Done()
			results <- withHermesCommandLock(filepath.Join(config, "config.yaml"), home, func() error { return nil })
		}(pair[0], pair[1])
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock order deadlocked")
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestHermesCommandLockRejectsSymlink(t *testing.T) {
	root := lockTestEnvironment(t)
	resource := filepath.Join(root, "resource")
	canonical, err := canonicalLockResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(root, "cache", "pipelock", "locks")
	if err := ensureHermesLockDir(lockDir); err != nil {
		t.Fatal(err)
	}
	path := hermesLockPath(lockDir, canonical)
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := withHermesCommandLock(filepath.Join(resource, "config.yaml"), resource, func() error { return nil }); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestHermesLockCanonicalizesExistingSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := canonicalLockResource(filepath.Join(alias, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(realDir, "missing")
	if got != want {
		t.Fatalf("canonical path = %s; want %s", got, want)
	}
}
