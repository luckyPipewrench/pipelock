// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestA2AURLCoreFloorBehindEarlierStage pins that a core credential in an A2A
// URL blocks even when an earlier URL stage (here the blocklist) ended the
// scan first, with the A2A action set to warn.
func TestA2AURLCoreFloorBehindEarlierStage(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	a2aCfg := enabledA2ACfg()
	a2aCfg.Action = config.ActionWarn
	for _, kind := range []string{"core", "policy"} {
		uri := "https://blocked.example/v1"
		want := config.ActionWarn
		if kind == "core" {
			uri += "?token=" + "AKIA" + "IOSFODNN7EXAMPLE"
			want = config.ActionBlock
		}
		t.Run("header/"+kind, func(t *testing.T) {
			got := ScanA2AHeaders(context.Background(), http.Header{"A2a-Extensions": []string{uri}}, sc, a2aCfg)
			if got.Clean || got.Action != want {
				t.Fatalf("action = %q clean=%v, want %q: %+v", got.Action, got.Clean, want, got)
			}
		})
		t.Run("field/"+kind, func(t *testing.T) {
			// The raw pass also sees the credential within budget, so assert
			// on the URL leaf's own findings as well as the action.
			got := ScanA2ARequestBody(context.Background(), []byte(`{"url":"`+uri+`"}`), sc, a2aCfg)
			if got.Clean || got.Action != want {
				t.Fatalf("action = %q clean=%v, want %q: %+v", got.Action, got.Clean, want, got)
			}
			hasCoreURL := false
			for _, f := range got.URLFindings {
				hasCoreURL = hasCoreURL || scanner.IsCoreCriticalResult(f)
			}
			if hasCoreURL != (kind == "core") {
				t.Fatalf("core URL finding = %v, want %v: %+v", hasCoreURL, kind == "core", got.URLFindings)
			}
		})
	}
}
