// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package baseline

func acquireIntegrityHighWaterLock(_ string) (func(), error) {
	return func() {}, nil
}
