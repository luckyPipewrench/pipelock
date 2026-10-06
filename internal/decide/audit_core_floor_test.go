// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"fmt"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestDecide_AuditModeKeepsCoreCredentialFloor pins the hook decision to the
// proxy contract: enforce: false allows ordinary findings, but a built-in core
// credential is still denied. Enforce mode denies both.
func TestDecide_AuditModeKeepsCoreCredentialFloor(t *testing.T) {
	values := map[string]string{
		"core":     "AKIA" + "IOSFODNN7EXAMPLE",
		"ordinary": "auditprobe-" + "12345678",
		// A core credential bound for a blocklisted host: the blocklist ends
		// the URL scan before its core floor stage.
		"coreblocked": "AKIA" + "IOSFODNN7EXAMPLE",
	}
	for _, enforce := range []bool{false, true} {
		for kind, value := range values {
			for _, event := range []EventKind{EventShellExecution, EventWebFetch} {
				if kind == "coreblocked" && event != EventWebFetch {
					continue
				}
				t.Run(fmt.Sprintf("enforce=%v/%s/%s", enforce, kind, event), func(t *testing.T) {
					cfg := config.Defaults()
					cfg.DLP.ScanEnv = false
					cfg.Enforce = &enforce
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Audit Floor Probe", Regex: `auditprobe-[0-9]{8}`, Severity: config.SeverityCritical})
					cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
					cfg.ApplyDefaults()
					cfg.Internal = nil
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					action := Action{Source: "cursor", Kind: event}
					if event == EventWebFetch {
						host := "api.vendor.example"
						if kind == "coreblocked" {
							host = "blocked.example"
						}
						action.WebFetch = &WebFetchPayload{URL: "https://" + host + "/x?token=" + value}
					} else {
						action.Shell = &ShellPayload{Command: "echo " + value, CWD: "/tmp"}
					}
					decision := Decide(context.Background(), cfg, sc, nil, action)
					want := Deny
					if !enforce && kind == "ordinary" {
						want = Allow
					}
					if decision.Outcome != want {
						t.Fatalf("outcome = %s, want %s; evidence = %+v", decision.Outcome, want, decision.Evidence)
					}
				})
			}
		}
	}
}
