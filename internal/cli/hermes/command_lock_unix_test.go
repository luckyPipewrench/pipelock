//go:build !windows

package hermes

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHermesLockDirectoryRejectsWritable(t *testing.T) {
	root := t.TempDir()
	for _, mode := range []os.FileMode{0o770, 0o707} {
		path := filepath.Join(root, "locks")
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := ensureHermesLockDir(path); err == nil {
			t.Errorf("accepted mode %o", mode)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHermesLockTimeoutNamesFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "held.lock")
	release, err := acquireHermesLock(path, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	called := false
	unlock, err := acquireHermesLock(path, time.Now())
	if unlock != nil {
		called = true
		unlock()
	}
	if err == nil || called || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "another pipelock hermes install or rollback") {
		t.Fatalf("timeout err=%v acquired=%v", err, called)
	}
}

func TestHermesLockFileRejectsWrongOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	// An existing owner-mismatched inode must fail before any flock attempt.
	// Creation of that inode requires a privileged account, so exercise the
	// ownership predicate directly with a known foreign uid.
	if hermesLockFileOwnerOK(0) {
		t.Fatal("accepted foreign owner")
	}
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if !hermesLockFileOwnerOK(owner.Uid) {
		t.Fatal("rejected invoking owner")
	}
}

func TestHermesLockDirectoryRejectsWrongOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	if hermesLockDirSafe(os.ModeDir|0o700, 0) {
		t.Fatal("accepted directory owned by another uid")
	}
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !hermesLockDirSafe(info.Mode(), info.Sys().(*syscall.Stat_t).Uid) {
		t.Fatal("rejected invoking user's directory")
	}
}

func TestHermesLockRejectsWritableCacheRoot(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeMode := os.FileMode(0o777)
	if err := os.Chmod(cache, unsafeMode); err != nil {
		t.Fatal(err)
	}
	if err := ensureHermesLockDir(filepath.Join(cache, "pipelock", "locks")); err == nil {
		t.Fatal("accepted writable cache root")
	}
}

// A symlinked cache root is followed; the lock still works under it.
func TestHermesCommandLockFollowsSymlinkedCacheRoot(t *testing.T) {
	root := t.TempDir()
	realCache := filepath.Join(root, "real-cache")
	if err := os.Mkdir(realCache, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "cache")
	if err := os.Symlink(realCache, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", link)
	ran := false
	if err := withHermesCommandLock(filepath.Join(root, "cfg", "config.yaml"), filepath.Join(root, "home"), func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("lock under a symlinked cache root: err=%v ran=%v", err, ran)
	}
}
