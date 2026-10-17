// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestJSONInspectionAPIFragmentsWarn(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	buffer := scanner.NewFragmentBuffer(65536, 10, 300)
	t.Cleanup(buffer.Close)
	ceeCfg := cfg.CrossRequestDetection
	ceeCfg.Action = config.ActionWarn
	for i, part := range []string{`[1e`, `10001]`} {
		result := checkCrossRequestFragment(t.Context(), buffer, sc, nil, ceeCfg, "caller", "inspection", "request", []byte(part))
		if result.Blocked != (i == 1) {
			t.Fatalf("fragment %d blocked=%v matched=%v action=%s", i, result.Blocked, result.Matched, result.Action)
		}
	}
}
