// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"strings"
	"testing"
)

func TestNonLinuxProcessStatsAreUnavailable(t *testing.T) {
	old := readProcessStat
	readProcessStat = func(string) ([]byte, error) { t.Fatal("non-Linux stats touched procfs"); return nil, nil }
	t.Cleanup(func() { readProcessStat = old })
	_, err := readProc(1)
	if err == nil || !strings.Contains(err.Error(), "not linux") {
		t.Fatalf("process stats: %v", err)
	}
}
