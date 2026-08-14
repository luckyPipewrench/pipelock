// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

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
