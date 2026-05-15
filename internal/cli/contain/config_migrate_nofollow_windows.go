// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

import (
	"fmt"
	"io"
	"os"
)

func readRegularFileNoFollow(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // Windows has no O_NOFOLLOW; caller rejects symlink components before opening.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(f)
}
