//go:build windows

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"os"
	"path/filepath"
)

func openRegularNonblocking(path string) (*os.File, error) {
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
	return file, nil
}
