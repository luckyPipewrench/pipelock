//go:build !unix

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "testing"

func skipIfPermissionsBypassed(t *testing.T) {
	t.Helper()
	t.Skip("permission-denial test requires Unix permissions")
}
