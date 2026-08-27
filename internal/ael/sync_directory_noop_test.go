// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows || darwin

package ael

import "testing"

func TestSyncDirectoryIsNoop(t *testing.T) {
	t.Parallel()
	if err := syncDirectory("ignored"); err != nil {
		t.Fatalf("syncDirectory no-op: %v", err)
	}
}
