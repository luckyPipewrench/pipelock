// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package commitmentkey

import (
	"errors"
)

var errSecureIOUnsupported = errors.New("secure commitment keyring storage is unsupported on this operating system")

func ensureParent(string) error { return errSecureIOUnsupported }

func readSecure(path string) ([]byte, error) {
	return readSecureLimited(path, maxBytes, "commitment keyring", ErrInvalidKeyring)
}

func readSecureLimited(string, int64, string, error) ([]byte, error) {
	return nil, errSecureIOUnsupported
}

func writeSecureNew(string, []byte) error { return errSecureIOUnsupported }

func writeSecureReplace(string, []byte) error { return errSecureIOUnsupported }
