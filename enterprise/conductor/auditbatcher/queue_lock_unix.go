//go:build enterprise && !windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package auditbatcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireQueueLock takes an exclusive, non-blocking advisory lock on a .lock
// file under the queue root. A second process on the same host / local
// filesystem opening the same dir fails closed with ErrQueueLocked rather than
// silently interleaving Enqueue/Claim/Drop across two independent in-process
// mutexes. This is not a distributed lock for cross-host shared PVCs. The flock
// is released when the fd is closed (Close) or when the holding process dies, so
// a crash never deadlocks.
func acquireQueueLock(dir string) (*os.File, error) {
	path := filepath.Join(filepath.Clean(dir), lockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf("auditbatcher: open queue lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrQueueLocked, path)
		}
		return nil, fmt.Errorf("auditbatcher: lock queue %s: %w", path, err)
	}
	return f, nil
}

func (q *Queue) releaseLock() error {
	if q.lockFile == nil {
		return nil
	}
	f := q.lockFile
	q.lockFile = nil
	// Closing the fd implicitly releases the flock; an explicit Flock(LOCK_UN)
	// first makes the release deterministic even if the fd is later dup'd.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if err := f.Close(); err != nil {
		return fmt.Errorf("auditbatcher: close queue lock: %w", err)
	}
	return nil
}

func ignoreDirSyncError(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}
