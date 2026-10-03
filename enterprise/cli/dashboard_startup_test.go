//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
	"github.com/spf13/cobra"
)

type dashboardStartupSink struct{ closes atomic.Int32 }

func (*dashboardStartupSink) Emit(context.Context, emit.Event) error { return nil }
func (s *dashboardStartupSink) Close() error                         { s.closes.Add(1); return nil }

func dashboardStartupOptions(t *testing.T) dashboardServeOptions {
	t.Helper()
	t.Setenv(license.EnvLicenseCRLFile, "")
	return dashboardServeOptions{listen: "127.0.0.1:0", receiptDir: t.TempDir(), authTokenFile: writeDashTokenFile(t)}
}

func TestDashboardStartupOptionalFailure(t *testing.T) {
	for _, name := range []string{"exemption", "legal hold", "conductor", "OIDC"} {
		t.Run(name, func(t *testing.T) {
			opts := dashboardStartupOptions(t)
			bad := filepath.Join(t.TempDir(), "invalid.json")
			if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			var want string
			switch name {
			case "exemption":
				opts.exemptionStore = bad
				_, err := dashboard.OpenExemptionStore(bad)
				if err == nil {
					t.Fatal("invalid fixture accepted")
				}
				want = "--exemption-store: " + err.Error()
			case "legal hold":
				opts.legalHoldStore = bad
				_, err := dashboard.OpenLegalHoldStore(bad)
				if err == nil {
					t.Fatal("invalid fixture accepted")
				}
				want = "--legal-hold-store: " + err.Error()
			case "OIDC":
				opts.oidcIssuer = "https://identity.example"
				opts.oidcAudience = "dashboard"
				opts.oidcRoleClaim = "groups"
				opts.oidcRoleMap = "{"
				_, err := parseDashboardOIDCRoleMap(opts.oidcRoleMap)
				if err == nil {
					t.Fatal("invalid OIDC fixture accepted")
				}
				want = err.Error()
			case "conductor":
				opts.conductorOrg = "test-org"
				want = "--conductor-url is required when any conductor dashboard source option is set"
			}
			cmd := &cobra.Command{}
			cmd.SetErr(io.Discard)
			prepared := &dashboardPreparedRuntime{}
			defer prepared.close()
			err := prepared.prepare(cmd, opts, license.License{})
			if err == nil || err.Error() != want {
				t.Fatalf("prepare error = %v, want %q", err, want)
			}
			if prepared.server != nil {
				t.Fatal("failed preparation published a server")
			}
			if prepared.emitter == nil {
				t.Fatal("partial preparation lost emitter ownership")
			}
			sink := &dashboardStartupSink{}
			prepared.emitter.ReloadSinks([]emit.Sink{sink})
			prepared.close()
			prepared.close()
			if got := sink.closes.Load(); got != 1 {
				t.Fatalf("sink closes = %d, want 1", got)
			}
			if prepared.emitter != nil {
				t.Fatal("cleanup retained emitter")
			}
			if err := runDashboardServe(cmd, opts, license.License{}); err == nil || err.Error() != want {
				t.Fatalf("run error = %v, want %q", err, want)
			}
		})
	}
}

func TestDashboardStartupClose(t *testing.T) {
	for _, state := range []string{"empty", "partial", "complete"} {
		t.Run(state, func(t *testing.T) {
			sink := &dashboardStartupSink{}
			prepared := &dashboardPreparedRuntime{}
			if state != "empty" {
				prepared.emitter = emit.NewEmitter("startup-test", sink)
			}
			if state == "complete" {
				prepared.server = &http.Server{ReadHeaderTimeout: time.Second}
			}
			prepared.close()
			prepared.close()
			want := int32(1)
			if state == "empty" {
				want = 0
			}
			if got := sink.closes.Load(); got != want {
				t.Fatalf("sink closes = %d, want %d", got, want)
			}
			if prepared.emitter != nil {
				t.Fatal("cleanup retained emitter")
			}
		})
	}
}

func TestDashboardStartupCancellation(t *testing.T) {
	opts := dashboardStartupOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	out := &dashSyncBuffer{}
	cmd.SetOut(out)
	cmd.SetErr(io.Discard)
	prepared := &dashboardPreparedRuntime{}
	defer prepared.close()
	if err := prepared.prepare(cmd, opts, license.License{}); err != nil {
		t.Fatal(err)
	}
	sink := &dashboardStartupSink{}
	prepared.emitter.ReloadSinks([]emit.Sink{sink})
	done := make(chan error, 1)
	go func() { done <- prepared.serve(cmd, opts) }()
	testwait.For(t, 5*time.Second, func() bool { return out.contains("dashboard listening on http://") }, "dashboard listener readiness")
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not terminate after cancellation")
	}
	prepared.close()
	prepared.close()
	if got := sink.closes.Load(); got != 1 {
		t.Fatalf("sink closes = %d, want 1", got)
	}
}

func TestDashboardStartupAlreadyCanceled(t *testing.T) {
	opts := dashboardStartupOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	prepared := &dashboardPreparedRuntime{}
	defer prepared.close()
	if err := prepared.prepare(cmd, opts, license.License{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- prepared.serve(cmd, opts) }()
	select {
	case err := <-done:
		// A canceled listen may fail before binding, or bind and immediately shut down.
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("already canceled serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("already canceled serve did not terminate")
	}
}
