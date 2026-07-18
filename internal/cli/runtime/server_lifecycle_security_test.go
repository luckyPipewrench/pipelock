// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testport"
)

func TestServer_StartLaterBindFailureReleasesEarlierMetricsListener(t *testing.T) {
	testport.WithRetry(t, 1, func(addrs []string) error {
		metricsAddr := addrs[0]

		scanBlocker, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen scan blocker: %v", err)
		}
		defer func() { _ = scanBlocker.Close() }()

		s, stderr := newTestServer(t, func(o *ServerOpts) {
			o.Listen = serverTestEphemeralListen
			o.ListenChanged = true
		})
		s.cfg.MetricsListen = metricsAddr
		s.cfg.ScanAPI.Listen = scanBlocker.Addr().String()

		err = s.Start(context.Background())
		if err == nil {
			t.Fatal("Start returned nil, want scan API bind failure")
		}
		if !strings.Contains(err.Error(), "scan_api.listen bind") {
			if testport.IsBindCollision(err) && strings.Contains(err.Error(), "metrics_listen bind") {
				return err
			}
			t.Fatalf("Start error = %v, want scan_api.listen bind failure", err)
		}
		if !stderr.contains("metrics listening on " + metricsAddr) {
			t.Fatalf("metrics listener never started before scan API failure:\n%s", stderr.String())
		}

		rebound, bindErr := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", metricsAddr)
		if bindErr != nil {
			t.Fatalf("metrics listener remained bound after Start returned: %v", bindErr)
		}
		_ = rebound.Close()
		return nil
	})
}
