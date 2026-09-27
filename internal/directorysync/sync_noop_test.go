// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package directorysync

import "testing"

func TestSyncDirectoryIsNoop(t *testing.T) {
	t.Parallel()
	if err := Sync("ignored"); err != nil {
		t.Fatalf("Sync no-op: %v", err)
	}
}
