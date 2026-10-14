// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardJSONRequestBody(t *testing.T) {
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	s := scanner.MustNew(cfg)
	t.Cleanup(s.Close)
	card := "41111111" + "11111111"
	for _, redaction := range []bool{false, true} {
		for _, tt := range []struct {
			name, body string
			clean      bool
		}{
			{"metrics", `{"rows":[{"ctr":0.` + card + `,"position":4.` + card + `}]}`, true},
			{"integer", `{"n":` + card + `}`, false},
			{"integer decimal", `{"n":` + card + `.0}`, false},
			{"mantissa", `{"n":` + card + `.1}`, false},
			{"exponent", `{"n":4.11111111` + `1111111e15}`, true},
			{"malformed", `{ctr:0.` + card + `}`, false},
			{"trailing document", `{"ctr":0.` + card + `} {}`, false},
		} {
			t.Run(tt.name+map[bool]string{false: "/scan", true: "/redact"}[redaction], func(t *testing.T) {
				req := BodyScanRequest{Body: strings.NewReader(tt.body), ContentType: "application/json", MaxBytes: 1 << 20, Scanner: s, Action: config.ActionBlock}
				if redaction {
					req.RedactMatcher = redact.NewDefaultMatcher()
				}
				out, result := scanRequestBody(t.Context(), req)
				if result.Clean != tt.clean {
					t.Fatalf("clean=%v want=%v result=%+v", result.Clean, tt.clean, result)
				}
				if tt.clean && string(out) != tt.body {
					t.Fatalf("metrics changed: %s", out)
				}
				if !tt.clean && result.Action != config.ActionBlock {
					t.Fatalf("non-clean request did not block: %+v", result)
				}
			})
		}
	}
}
