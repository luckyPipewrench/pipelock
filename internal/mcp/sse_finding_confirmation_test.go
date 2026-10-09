// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestGenericSSEFindingConfirmation(t *testing.T) {
	for _, shape := range []string{"injection", "dlp", "exempt injection"} {
		for _, failed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%t", shape, failed), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: "POLICY_MARKER"}}
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				streamCfg := enabledSSECfg()
				streamCfg.Action = config.ActionWarn
				payload := "POLICY_MARKER"
				if shape == "dlp" {
					payload = fakeAWSKey()
				}
				if shape == "exempt injection" {
					streamCfg.Action = config.ActionBlock
				}
				clean := "data: {\"text\":\"hello\"}\n\n"
				warned := fmt.Sprintf("data: {\"text\":%q}\n\n", payload)
				body := clean + warned + clean
				var out bytes.Buffer
				calls := 0
				failure := errors.New("confirmation unavailable")
				err := ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(body), &out, nil, sc, streamCfg, GenericSSEScanOptions{
					ResponseScanExempt: shape == "exempt injection",
					ConfirmFinding: func(finding error) error {
						calls++
						if !errors.Is(finding, ErrSSEStreamFinding) {
							t.Fatalf("confirmation received a non-finding: %v", finding)
						}
						if strings.Contains(out.String(), payload) {
							t.Fatal("finding delivered before confirmation")
						}
						if failed {
							return failure
						}
						return nil
					},
				})
				if calls != 1 {
					t.Fatalf("confirmation calls=%d, want one warned event", calls)
				}
				if failed {
					if !errors.Is(err, failure) || errors.Is(err, ErrSSEStreamFinding) {
						t.Fatalf("confirmation failure classification: %v", err)
					}
					if out.String() != clean {
						t.Fatalf("failed event or later event delivered: %q", out.String())
					}
				} else if err != nil || out.String() != body {
					t.Fatalf("confirmed stream changed: err=%v body=%q", err, out.String())
				}
			})
		}
	}
}
