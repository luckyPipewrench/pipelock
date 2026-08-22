// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestReload_CEEPathEnforcementSurvivesUnrelatedReload asserts ENFORCEMENT, not
// just retained bytes. State can survive a reload while admission quietly stops
// consulting the path stream, and a byte-count assertion passes either way. Here
// one half of a split secret is seeded, an unrelated reload happens, and the
// completing half is submitted through real admission, which must block.
func TestReload_CEEPathEnforcementSurvivesUnrelatedReload(t *testing.T) {
	half1, half2 := pathSecretHalves()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionBlock
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
	cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false

	sc := scanner.MustNew(cfg)
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	const sessionKey = "reload-enforce"
	admit := func(path string) ceeAdmission {
		u, parseErr := url.Parse("http://example.com" + path)
		if parseErr != nil {
			t.Fatalf("parse: %v", parseErr)
		}
		return p.admitCurrentCEE(t.Context(), ceeAdmitRequest{
			SessionKey: sessionKey, PathPayload: pathSegments(u),
			TargetURL: u.String(), Agent: "agent", ClientIP: "1.2.3.4",
			RequestID: "req", IncludeFragments: true,
		})
	}

	if res := admit("/upload/" + half1); res.Result.Blocked {
		t.Fatal("first half blocked on its own")
	}

	unrelated := cfg.Clone()
	unrelated.KillSwitch.Message = "unrelated reload"
	if ok := p.Reload(unrelated, scanner.MustNew(unrelated)); !ok {
		t.Fatal("unrelated reload failed")
	}

	if res := admit("/upload/" + half2); !res.Result.Blocked {
		t.Fatal("path CEE stopped enforcing after an unrelated reload")
	}
}
