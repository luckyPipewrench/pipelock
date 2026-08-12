// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// openDurableAuditFile retains descriptor binding on platforms that do not
// expose Unix O_NOFOLLOW and O_NONBLOCK flags through the standard library.
func openDurableAuditFile(path string) (*os.File, bool, error) {
	cleanPath := filepath.Clean(path)
	file, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		file, err = os.OpenFile(cleanPath, os.O_APPEND|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return nil, false, err
	}
	return file, created, nil
}
