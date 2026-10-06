// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestActualProxyHealthProducer(t *testing.T) {
	t.Parallel()
	for _, forward := range []bool{true, false} {
		t.Run(map[bool]string{true: "forward enabled", false: "forward disabled"}[forward], func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.ForwardProxy.Enabled = forward
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := proxy.New(cfg, audit.NewNop(), sc, metrics.New())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(p.Handler())
			t.Cleanup(server.Close)
			launched := false
			cmd := newCmd(dependencies{launch: func(_ *cobra.Command, _, _ []string) error { launched = true; return nil }})
			cmd.SetArgs([]string{"--proxy-url", server.URL, "--", "command"})
			cmd.SetErr(&bytes.Buffer{})
			err = cmd.Execute()
			if forward {
				if err != nil || !launched {
					t.Fatalf("real proxy refused: launched=%v err=%v", launched, err)
				}
			} else if launched || err == nil || !strings.Contains(err.Error(), "forward proxy is disabled") {
				t.Fatalf("real proxy wrongly accepted: launched=%v err=%v", launched, err)
			}
		})
	}
}
