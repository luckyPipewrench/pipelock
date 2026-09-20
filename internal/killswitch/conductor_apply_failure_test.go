// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestController_ConductorApplyFailureSurvivesStaleClear(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.Message = "policy recovery required"
	controller := New(cfg)
	controller.SetConductorApplyFailure(true, "apply outcome unknown")
	controller.SetConductorStale(false, "")

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch", nil)
	request.RemoteAddr = "203.0.113.8:4040"
	decision := controller.IsActiveHTTP(request)
	if !decision.Active || decision.Source != "conductor_apply_failure" {
		t.Fatalf("decision after stale clear = %+v, want conductor_apply_failure deny", decision)
	}
	if !controller.Sources()["conductor_apply_failure"] || !controller.ConductorApplyFailure() {
		t.Fatal("uncertainty status disagrees with admission")
	}

	controller.SetConductorApplyFailure(false, "")
	if decision := controller.IsActiveHTTP(request); decision.Active || controller.ConductorApplyFailure() {
		t.Fatalf("decision after resolved apply = %+v, want allowed", decision)
	}
	controller.SetConductorApplyFailure(true, "")
	if decision := controller.IsActiveHTTP(request); !decision.Active || decision.Message != cfg.KillSwitch.Message {
		t.Fatalf("empty apply message did not retain configured denial: %+v", decision)
	}
}

func TestController_ConductorApplyFailureRequiresConsistentPolicyForExemptIP(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.AllowlistIPs = []string{"203.0.113.8/32"}
	controller := New(cfg)
	controller.SetConductorRemote(true, "operator emergency stop")
	for _, target := range []string{"/fetch", "http://api.vendor.example/health"} {
		t.Run(target, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			request.RemoteAddr = "203.0.113.8:4040"
			if controller.IsActiveHTTP(request).Active || controller.IsActiveForIP("203.0.113.8").Active {
				t.Fatal("ordinary operator emergency exemption was lost")
			}
			controller.SetConductorApplyFailure(true, "policy is not committed")
			if !controller.IsActiveHTTP(request).Active || !controller.IsActiveForIP("203.0.113.8").Active {
				t.Error("uncertain policy forwarded traffic for an exempt client")
			}
			controller.SetConductorStale(false, "")
			if !controller.IsActiveMCP([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)).Active {
				t.Error("uncertain policy admitted an MCP request")
			}
			controller.SetConductorApplyFailure(false, "")
			if controller.IsActiveHTTP(request).Active || controller.IsActiveForIP("203.0.113.8").Active {
				t.Fatal("consistent policy did not restore the operator exemption")
			}
		})
	}
}
