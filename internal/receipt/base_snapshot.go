// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// WithBaseHistorySnapshot binds enumeration, verification and report assembly
// to the same base inventory. The caller must hold output and side effects
// until it returns. This detects observed changes, not an atomic snapshot.
func WithBaseHistorySnapshot(dir, base string, consume func() error) error {
	if consume == nil {
		return errors.New("base snapshot consumer is required")
	}
	root, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	before, err := baseHistoryInventory(dir, base)
	if err != nil {
		return err
	}
	result := consume()
	after, inventoryErr := baseHistoryInventory(dir, base)
	endRoot, rootErr := os.Lstat(dir)
	if inventoryErr != nil || rootErr != nil || !os.SameFile(root, endRoot) || before != after {
		return recorder.ErrEvidenceChanged
	}
	return result
}

func baseHistoryInventory(dir, base string) ([32]byte, error) {
	ix, err := indexRecorderFiles(dir)
	if err != nil {
		return [32]byte{}, err
	}
	shards, err := fingerprintBaseShards(ix, baseSessions(ix, base))
	if err != nil {
		return [32]byte{}, err
	}
	names, err := chainLinkFileNames(dir)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write(shards[:])
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return [32]byte{}, err
		}
		stamp, err := recorder.EvidenceMetadataIdentity(path, info)
		if err != nil {
			return [32]byte{}, err
		}
		_, _ = fmt.Fprintf(h, "%q %q %d %d %d\n", name, stamp, info.Mode(), info.Size(), info.ModTime().UnixNano())
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
