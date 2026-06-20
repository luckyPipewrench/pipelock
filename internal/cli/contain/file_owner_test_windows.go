// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package contain

func fakeFileSysWithUID(_ uint32) any {
	return nil
}
