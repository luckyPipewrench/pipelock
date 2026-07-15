// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Verifier inputs are commonly supplied by a different trust domain. Keep the
// ceiling aligned with the maximum evidence shard accepted by the receipt
// verifier so a malformed standalone artifact cannot allocate without bound.
const maxVerifierInputBytes int64 = 8 << 20

func readVerifierFile(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.Base(clean))
	closeErr := root.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file")
	}
	if info.Size() > maxVerifierInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxVerifierInputBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxVerifierInputBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxVerifierInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxVerifierInputBytes)
	}
	return data, nil
}
