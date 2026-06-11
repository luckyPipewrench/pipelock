//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

func runCommand(t *testing.T, fn func(*cobra.Command) error) (string, error) {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())
	err := fn(cmd)
	return out.String(), err
}

func TestRunAuditQueryListAndGet(t *testing.T) {
	var gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"batches":[],"count":0}`))
	})
	clientOpts := newTestClientServer(t, "auditor-token", handler)

	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runAuditQuery(cmd, auditQueryOptions{client: clientOpts, orgID: "org-main", fleetID: "prod", limit: 5})
	})
	if err != nil {
		t.Fatalf("runAuditQuery(list) error = %v", err)
	}
	if !strings.Contains(out, `"count":0`) {
		t.Fatalf("list output = %q", out)
	}
	if !strings.Contains(gotPath, "org_id=org-main") || !strings.Contains(gotPath, "fleet_id=prod") || !strings.Contains(gotPath, "limit=5") {
		t.Fatalf("list path = %q", gotPath)
	}

	_, err = runCommand(t, func(cmd *cobra.Command) error {
		return runAuditQuery(cmd, auditQueryOptions{client: clientOpts, orgID: "org-main", fleetID: "prod", instanceID: "i-1", batchID: "audit-batch-1"})
	})
	if err != nil {
		t.Fatalf("runAuditQuery(get) error = %v", err)
	}
	if !strings.HasPrefix(gotPath, "/api/v1/conductor/audit/batches/audit-batch-1?") {
		t.Fatalf("get path = %q", gotPath)
	}
}

func TestRunAuditQueryValidatesArgs(t *testing.T) {
	clientOpts := newTestClientServer(t, "auditor-token", http.NotFoundHandler())
	cases := []struct {
		name string
		opts auditQueryOptions
		want string
	}{
		{"missing org", auditQueryOptions{client: clientOpts, fleetID: "prod"}, "--org-id is required"},
		{"batch without fleet", auditQueryOptions{client: clientOpts, orgID: "org-main", batchID: "b1", instanceID: "i-1"}, "--batch-id requires"},
		{"batch without instance", auditQueryOptions{client: clientOpts, orgID: "org-main", batchID: "b1", fleetID: "prod"}, "--batch-id requires"},
		{"negative limit", auditQueryOptions{client: clientOpts, orgID: "org-main", limit: -1}, "--limit must be non-negative"},
		{"batch id with slash", auditQueryOptions{client: clientOpts, orgID: "org-main", fleetID: "prod", instanceID: "i-1", batchID: "a/b"}, "must not contain"},
		{"batch id with query", auditQueryOptions{client: clientOpts, orgID: "org-main", fleetID: "prod", instanceID: "i-1", batchID: "a?org_id=evil"}, "must not contain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runCommand(t, func(cmd *cobra.Command) error {
				return runAuditQuery(cmd, tc.opts)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runAuditQuery() error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestRunFleetStatusTableAndJSON(t *testing.T) {
	body := `{"followers":[{"org_id":"org-main","fleet_id":"prod","instance_id":"pl-prod-1","environment":"prod","audit_key_id":"k1","enrolled_at":"2026-05-24T12:00:00Z","active":true}],"count":1}`
	var gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)

	// Table output.
	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err != nil {
		t.Fatalf("runFleetStatus(table) error = %v", err)
	}
	if !strings.Contains(out, "pl-prod-1") || !strings.Contains(out, "1 follower(s)") || !strings.Contains(out, "INSTANCE") {
		t.Fatalf("table output = %q", out)
	}
	if !strings.Contains(gotPath, "/api/v1/conductor/followers?") || !strings.Contains(gotPath, "org_id=org-main") {
		t.Fatalf("path = %q", gotPath)
	}

	// JSON passthrough.
	out, err = runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main", jsonOut: true}, false)
	})
	if err != nil {
		t.Fatalf("runFleetStatus(json) error = %v", err)
	}
	if !strings.Contains(out, `"count":1`) {
		t.Fatalf("json output = %q", out)
	}
}

func TestRunFleetStatusEmptyRoster(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"followers":[],"count":0}`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err != nil {
		t.Fatalf("runFleetStatus(empty) error = %v", err)
	}
	if !strings.Contains(out, "no enrolled followers") {
		t.Fatalf("empty output = %q", out)
	}
}

func TestRunFleetStatusValidatesArgs(t *testing.T) {
	clientOpts := newTestClientServer(t, "admin-token", http.NotFoundHandler())
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "--org-id is required") {
		t.Fatalf("runFleetStatus() error = %v, want --org-id required", err)
	}
	_, err = runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main", limit: -2}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "--limit must be non-negative") {
		t.Fatalf("runFleetStatus() error = %v, want limit error", err)
	}
}

func TestObservabilityCommandsRegistered(t *testing.T) {
	root := Cmd()
	want := map[string]bool{"audit": false, "fleet": false, "followers": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("command %q not registered on conductor root", name)
		}
	}
	// audit has a query subcommand; fleet has a status subcommand.
	assertSubcommand(t, root, "audit", "query")
	assertSubcommand(t, root, "fleet", "status")
}

func TestObservabilityCommandsFailClosedWithoutFleetLicense(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	for _, args := range [][]string{
		{"audit", "query", "--org-id", "org-main"},
		{"fleet", "status", "--org-id", "org-main"},
		{"followers", "--org-id", "org-main"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := Cmd()
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			err := cmd.Execute()
			if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
				t.Fatalf("Execute(%v) error = %v, want ErrFleetLicenseRequired", args, err)
			}
		})
	}
}

func TestRunFleetStatusRejectsMalformedJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "decode followers response") {
		t.Fatalf("runFleetStatus() error = %v, want decode error", err)
	}
}

func TestRunAuditQueryPropagatesTransportError(t *testing.T) {
	// A bad client cert path makes newConductorClient fail before any request.
	bad := newTestClientServer(t, "auditor-token", http.NotFoundHandler())
	bad.clientCertFile = "/does/not/exist.pem"
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runAuditQuery(cmd, auditQueryOptions{client: bad, orgID: "org-main"})
	})
	if err == nil || !strings.Contains(err.Error(), "operator client certificate") {
		t.Fatalf("runAuditQuery() error = %v, want client cert load error", err)
	}
}

func assertSubcommand(t *testing.T, root *cobra.Command, parent, child string) {
	t.Helper()
	for _, c := range root.Commands() {
		if c.Name() != parent {
			continue
		}
		for _, sc := range c.Commands() {
			if sc.Name() == child {
				return
			}
		}
		t.Fatalf("%q has no %q subcommand", parent, child)
	}
	t.Fatalf("parent %q not found", parent)
}
