// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

func requireKnownTools(t testing.TB, baseline *tools.ToolBaseline, names []string) {
	t.Helper()
	if err := baseline.SetKnownTools(names); err != nil {
		t.Fatalf("SetKnownTools: %v", err)
	}
}
