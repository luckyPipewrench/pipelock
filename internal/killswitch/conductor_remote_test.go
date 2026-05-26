// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestController_ConductorRemoteSource(t *testing.T) {
	cfg := config.Defaults()
	ks := New(cfg)
	ks.SetConductorRemote(true, "remote stop")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch", nil)
	req.RemoteAddr = "10.0.0.1:4321"
	d := ks.IsActiveHTTP(req)
	if !d.Active || d.Source != "conductor_remote" || d.Message != "remote stop" {
		t.Fatalf("decision = %+v, want active conductor_remote remote stop", d)
	}
	if !ks.Sources()["conductor_remote"] {
		t.Fatalf("Sources()[conductor_remote] = false, want true")
	}

	ks.SetConductorRemote(false, "")
	if d := ks.IsActiveHTTP(req); d.Active {
		t.Fatalf("decision after clear = %+v, want inactive", d)
	}
}
