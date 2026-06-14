//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

const streamStatusBody = `{
  "org_id": "org-main",
  "fleet_id": "prod",
  "stream_count": 1,
  "streams": [
    {
      "stream_key": "org-main prod prod abc",
      "org_id": "org-main",
      "fleet_id": "prod",
      "environment": "prod",
      "audience": {"instance_ids": ["*"]},
      "head_version": 2,
      "head_bundle_id": "bundle-v2",
      "head_bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "max_version": 2,
      "rolled_back": false,
      "bundle_chain": [
        {"bundle_id":"bundle-v1","version":1,"bundle_hash":"1111","created_at":"2026-05-24T12:00:00Z","min_pipelock_version":"1.2.3","published_at":"2026-05-24T12:00:00Z"},
        {"bundle_id":"bundle-v2","version":2,"bundle_hash":"2222","previous_bundle_hash":"1111","created_at":"2026-05-24T12:01:00Z","min_pipelock_version":"1.2.3","published_at":"2026-05-24T12:01:00Z"}
      ]
    }
  ],
  "active_remote_kills": [
    {"message_id":"kill-1","fleet_id":"prod","state":"active","counter":1,"reason":"stop","expires_at":"2026-05-24T13:00:00Z","published_at":"2026-05-24T12:00:00Z"}
  ],
  "active_rollback_authorizations": [
    {"authorization_id":"rb-1","fleet_id":"prod","current_version":2,"target_version":1,"reason":"bad bundle","created_at":"2026-05-24T12:00:00Z","expires_at":"2026-05-24T13:00:00Z","published_at":"2026-05-24T12:00:00Z"}
  ],
  "emergency_controls_read": true
}`

func TestRunStreamStatusTable(t *testing.T) {
	var gotPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(streamStatusBody))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)

	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main", fleetID: "prod"}, false)
	})
	if err != nil {
		t.Fatalf("runStreamStatus(table) error = %v", err)
	}
	for _, want := range []string{"HEAD_VERSION", "MAX_VERSION", "ROLLED_BACK", "bundle-v2", "1 stream(s)", "active remote kill", "kill-1", "active rollback authorization", "rb-1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q: %s", want, out)
		}
	}
	// HONESTY GUARD: the operator table must not invent per-follower applied
	// version / drift columns.
	for _, forbidden := range []string{"APPLIED_VERSION", "DRIFT", "LAST_CONTACT"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("table output leaked per-follower column %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(gotPath, "/api/v1/conductor/stream?") || !strings.Contains(gotPath, "org_id=org-main") || !strings.Contains(gotPath, "fleet_id=prod") {
		t.Fatalf("request path = %q", gotPath)
	}
}

func TestRunStreamStatusJSONPassthrough(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(streamStatusBody))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)

	// status --json and inspect (forceJSON) both emit the raw body.
	for _, force := range []bool{false, true} {
		out, err := runCommand(t, func(cmd *cobra.Command) error {
			return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main", jsonOut: true}, force)
		})
		if err != nil {
			t.Fatalf("runStreamStatus(json force=%v) error = %v", force, err)
		}
		if !strings.Contains(out, `"bundle_chain"`) || !strings.Contains(out, `"previous_bundle_hash"`) {
			t.Fatalf("json output missing chain fields (force=%v): %s", force, out)
		}
	}
}

func TestRunStreamStatusEmpty(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org_id":"org-main","stream_count":0,"streams":[],"active_remote_kills":[],"active_rollback_authorizations":[],"emergency_controls_read":true}`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err != nil {
		t.Fatalf("runStreamStatus(empty) error = %v", err)
	}
	if !strings.Contains(out, "no publication streams match the query") {
		t.Fatalf("empty output = %q", out)
	}
	// emergency_controls_read=true with zero kills/rollbacks must report the
	// emergency lists as affirmatively empty, not silently omit them.
	if !strings.Contains(out, "emergency controls: none active") {
		t.Fatalf("empty output missing 'none active' line: %q", out)
	}
}

// TestRunStreamStatusEmergencyControlsUnavailable proves the fail-loud
// requirement: when the control plane reports it could not read the emergency
// store (emergency_controls_read=false), the human table must warn that the
// kill/rollback list may be incomplete so an empty list is not mistaken for
// "no active emergency controls".
func TestRunStreamStatusEmergencyControlsUnavailable(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org_id":"org-main","stream_count":0,"streams":[],"active_remote_kills":[],"active_rollback_authorizations":[],"emergency_controls_read":false}`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	out, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err != nil {
		t.Fatalf("runStreamStatus(unavailable) error = %v", err)
	}
	if !strings.Contains(out, "emergency controls: NOT AVAILABLE (kill/rollback list may be incomplete)") {
		t.Fatalf("output missing NOT AVAILABLE warning: %q", out)
	}
	// The fail-loud warning must replace, not coexist with, the "none active"
	// affirmative — an unreadable store is not an empty store.
	if strings.Contains(out, "emergency controls: none active") {
		t.Fatalf("output must not claim 'none active' when the store is unreadable: %q", out)
	}
}

func TestRunStreamStatusValidatesArgs(t *testing.T) {
	clientOpts := newTestClientServer(t, "admin-token", http.NotFoundHandler())
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "--org-id is required") {
		t.Fatalf("runStreamStatus() error = %v, want --org-id required", err)
	}
}

func TestRunStreamStatusRejectsMalformedJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not-json`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "decode stream status response") {
		t.Fatalf("runStreamStatus() error = %v, want decode error", err)
	}
}

func TestRunStreamStatusPropagatesServerError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	})
	clientOpts := newTestClientServer(t, "admin-token", handler)
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: clientOpts, orgID: "org-main"}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("runStreamStatus() error = %v, want 403 status error", err)
	}
}

func TestRunStreamStatusPropagatesTransportError(t *testing.T) {
	bad := newTestClientServer(t, "admin-token", http.NotFoundHandler())
	bad.clientCertFile = "/does/not/exist.pem"
	_, err := runCommand(t, func(cmd *cobra.Command) error {
		return runStreamStatus(cmd, streamStatusOptions{client: bad, orgID: "org-main"}, false)
	})
	if err == nil || !strings.Contains(err.Error(), "operator client certificate") {
		t.Fatalf("runStreamStatus() error = %v, want client cert load error", err)
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash("short"); got != "short" {
		t.Fatalf("shortHash(short) = %q, want unchanged", got)
	}
	long := strings.Repeat("a", 64)
	got := shortHash(long)
	if !strings.HasPrefix(got, "aaaaaaaaaaaa") || !strings.HasSuffix(got, "…") || len(got) >= len(long) {
		t.Fatalf("shortHash(long) = %q, want truncated 12-char prefix with ellipsis", got)
	}
}

func TestStreamCommandsRegistered(t *testing.T) {
	root := Cmd()
	var stream *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "stream" {
			stream = c
		}
	}
	if stream == nil {
		t.Fatal("stream command not registered on conductor root")
	}
	assertSubcommand(t, root, "stream", "status")
	assertSubcommand(t, root, "stream", "inspect")
}

func TestStreamCommandsFailClosedWithoutFleetLicense(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	for _, args := range [][]string{
		{"stream", "status", "--org-id", "org-main"},
		{"stream", "inspect", "--org-id", "org-main"},
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
