// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestA2AStreamIncompleteInspectionIsScanError(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		for name, body := range map[string]string{
			"depth":     strings.Repeat(`{"payload":`, 65) + `{"text":"hello"}` + strings.Repeat("}", 65),
			"duplicate": `{"text":"hello","text":"goodbye"}`,
			"invalid":   `{"text":`,
			"benign":    `{"text":"hello"}`,
		} {
			t.Run(action+"/"+name, func(t *testing.T) {
				cfg := enabledA2ACfg()
				cfg.Action = action
				var out bytes.Buffer
				err := ScanA2AStream(t.Context(), strings.NewReader("data: "+body+"\n\n"), &out, nil, sc, cfg)
				if name == "benign" {
					if err != nil || !strings.Contains(out.String(), body) {
						t.Fatal("clean event refused")
					}
				} else if !errors.Is(err, ErrSSEStreamScanError) || errors.Is(err, ErrA2AStreamFinding) || out.Len() != 0 {
					t.Fatalf("incomplete inspection misclassified: scanError=%t finding=%t bytes=%d", errors.Is(err, ErrSSEStreamScanError), errors.Is(err, ErrA2AStreamFinding), out.Len())
				}
			})
		}
	}
}
