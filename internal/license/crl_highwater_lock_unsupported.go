//go:build aix || (wasip1 && wasm)

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import "errors"

// acquireCRLHighWaterLock fails closed where cross-process locking is absent.
func acquireCRLHighWaterLock(_ string) (func(), error) {
	return nil, errors.New("license CRL high-water locking unsupported on this platform")
}
