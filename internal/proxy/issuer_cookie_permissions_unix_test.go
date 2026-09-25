//go:build unix

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"os"
	"testing"
)

func skipIfPermissionsBypassed(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-denial test cannot run with root privileges")
	}
}
