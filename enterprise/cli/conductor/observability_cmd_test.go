//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
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
	bodyBytes, err := json.Marshal(followersResponse{
		Followers: []controlplane.FollowerFleetStatus{{
			FollowerSummary: controlplane.FollowerSummary{
				OrgID:       "org-main",
				FleetID:     "prod",
				InstanceID:  "pl-prod-1",
				Environment: "prod",
				AuditKeyID:  "k1",
				EnrolledAt:  time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
				Active:      true,
			},
			RuntimeStatus: &controlplane.FollowerRuntimeStatus{
				PipelockVersion:     "1.2.3",
				ActiveBundleID:      "bundle-1",
				ActiveBundleVersion: 7,
				LastSeenAt:          time.Date(2026, 5, 24, 12, 5, 6, 0, time.UTC),
			},
			Health: controlplane.FleetHealthApplyFailed,
			Drift:  "last_apply_failed",
		}},
		Count: 1,
	})
	if err != nil {
		t.Fatalf("marshal followers response: %v", err)
	}
	body := string(bodyBytes)
	var gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)

	// Table output.
	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runFleetStatus(cmd, fleetStatusOptions{client: clientOpts, orgID: "org-main", fleetID: "prod", instanceID: "pl-prod-1", limit: 25}, false)
	})
	if err != nil {
		t.Fatalf("runFleetStatus(table) error = %v", err)
	}
	for _, want := range []string{"INSTANCE", "pl-prod-1", "1.2.3", "bundle-1@7", "2026-05-24T12:05:06Z", "apply_failed", "last_apply_failed", "1 follower(s)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q: %q", want, out)
		}
	}
	for _, want := range []string{"org_id=org-main", "fleet_id=prod", "instance_id=pl-prod-1", "limit=25"} {
		if !strings.Contains(gotPath, want) {
			t.Fatalf("path %q missing %q", gotPath, want)
		}
	}
	if !strings.Contains(gotPath, "/api/v1/conductor/followers?") {
		t.Fatalf("path = %q", gotPath)
	}

	out, err = runCommand(t, func(cmd *cobra.Command) error {
		return writeFollowerTable(cmd, followersResponse{
			Followers: []controlplane.FollowerFleetStatus{{
				FollowerSummary: controlplane.FollowerSummary{InstanceID: "pl-prod-unknown"},
				RuntimeStatus:   &controlplane.FollowerRuntimeStatus{},
				Health:          controlplane.FleetHealthUnknown,
			}},
			Count: 1,
		})
	})
	if err != nil {
		t.Fatalf("writeFollowerTable(empty runtime fields) error = %v", err)
	}
	fields := strings.Fields(out)
	wantFields := []string{"pl-prod-unknown", "unknown", "-"}
	for _, want := range wantFields {
		if !slices.Contains(fields, want) {
			t.Fatalf("table fields %v missing %q from output %q", fields, want, out)
		}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("table output has %d line(s), want header and row: %q", len(lines), out)
	}
	headerFields := strings.Fields(lines[0])
	driftColumn := slices.Index(headerFields, "DRIFT")
	if driftColumn < 0 {
		t.Fatalf("header fields %v missing DRIFT column in output %q", headerFields, out)
	}
	var rowFields []string
	for _, line := range lines[1:] {
		cells := strings.Fields(line)
		if len(cells) > 0 && cells[0] == "pl-prod-unknown" {
			rowFields = cells
			break
		}
	}
	if len(rowFields) <= driftColumn {
		t.Fatalf("could not find complete pl-prod-unknown row for DRIFT column %d in output %q", driftColumn, out)
	}
	if got := rowFields[driftColumn]; got != "-" {
		t.Fatalf("drift placeholder = %q, want '-' in output %q", got, out)
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
