// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package license

func acquireCRLHighWaterLock(_ string) (func(), error) {
	return func() {}, nil
}
