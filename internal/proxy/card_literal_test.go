// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardLiteralRequestHeaders(t *testing.T) {
	cfg := testScannerConfig()
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, text := range []string{card, "0." + card, "[0." + card + "]", `{"n":0.` + card + `}`} {
		result := scanRequestHeaders(t.Context(), http.Header{"X-Api-Key": {text}}, cfg, s)
		if result == nil || result.Clean {
			t.Fatalf("string header received numeric relief: %q", text)
		}
	}
}
