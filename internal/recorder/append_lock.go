// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"fmt"
	"os"
	"path/filepath"
)

// acquireAppendLock serializes tail inspection and append for legacy sessions
// which can still have multiple writers. A shared evidence-presence lock cannot
// do this: inspecting another writer's in-progress append would report TORN.
// This lock contains no evidence or recovery metadata.
// One stable inode per directory bounds lock files across run sessions and
// rotations. Never unlink on unlock: waiters must lock the same inode.
func acquireAppendLock(dir string) (func(), error) {
	path := filepath.Join(filepath.Clean(dir), ".append.lock")
	f, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR|evidenceReadNoFollowFlag, filePermissions)
	if err != nil {
		return nil, fmt.Errorf("open evidence append lock: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat evidence append lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("evidence append lock is not a regular file")
	}
	if err := lockEvidenceAppend(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("acquire evidence append lock: %w", err)
	}
	return func() {
		_ = unlockEvidenceAppend(f)
		_ = f.Close()
	}, nil
}

// InspectSession runs a read-only integrity check while recorder writes are
// excluded. inspect must not call methods which take the recorder mutex.
func (r *Recorder) InspectSession(_ string, inspect func() error) error {
	if inspect == nil {
		return fmt.Errorf("evidence session inspection callback is required")
	}
	if r.IsNop() {
		return inspect()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, err := acquireAppendLock(r.cfg.Dir)
	if err != nil {
		return err
	}
	defer unlock()
	return inspect()
}
