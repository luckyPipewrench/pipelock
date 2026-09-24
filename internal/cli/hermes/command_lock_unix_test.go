//go:build !windows

package hermes

import (
	"os"
	"path/filepath"
	"strings"
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
	if !hermesLockFileOwnerOK(uint32(os.Getuid())) {
		t.Fatal("rejected invoking owner")
	}
}
