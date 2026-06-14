//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

// streamStatusHandler serves the given stream-status response for GET and a
// 200 for DELETE (rollback-authorization clear), so the recovery run* funcs can
// be exercised against a real client + TLS server.
func streamStatusHandler(t *testing.T, resp streamStatusResponse) http.Handler {
	t.Helper()
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal stream status: %v", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(body)
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"cleared":true}`))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func newRecoveryCmd(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetContext(t.Context())
	return cmd, &buf
}

func TestRunStoreDump_Success(t *testing.T) {
	resp := streamStatusResponse{OrgID: "org-main", FleetID: "prod", EmergencyControlsRead: true, StreamCount: 0}
	client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
	cmd, buf := newRecoveryCmd(t)

	if err := runStoreDump(cmd, storeDumpOptions{client: client, orgID: "org-main", fleetID: "prod"}); err != nil {
		t.Fatalf("runStoreDump: %v", err)
	}
	if !strings.Contains(buf.String(), `"org_id": "org-main"`) {
		t.Fatalf("store dump output missing pretty JSON: %s", buf.String())
	}
}

func TestRunKillStatus_Success(t *testing.T) {
	resp := streamStatusResponse{
		OrgID:                 "org-main",
		FleetID:               "prod",
		EmergencyControlsRead: true,
		ActiveRemoteKills: []controlplane.ActiveRemoteKill{
			{MessageID: "kill-1", FleetID: "prod", State: "active", Counter: 1, Reason: "incident"},
		},
	}
	client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
	cmd, buf := newRecoveryCmd(t)

	if err := runKillStatus(cmd, killStatusOptions{client: client, orgID: "org-main", fleetID: "prod"}); err != nil {
		t.Fatalf("runKillStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "kill-1") || !strings.Contains(out, "1 active remote kill") {
		t.Fatalf("kill status output unexpected: %s", out)
	}
}

func TestRunStreamReset_ClearsActiveRollbacks(t *testing.T) {
	resp := streamStatusResponse{
		OrgID:                 "org-main",
		FleetID:               "prod",
		EmergencyControlsRead: true,
		ActiveRollbacks: []controlplane.ActiveRollbackAuthorization{
			{AuthorizationID: "auth-1", TargetVersion: 4},
		},
	}
	client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
	cmd, buf := newRecoveryCmd(t)

	if err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", fleetID: "prod", confirm: true}); err != nil {
		t.Fatalf("runStreamReset: %v", err)
	}
	if !strings.Contains(buf.String(), "cleared 1 of 1") {
		t.Fatalf("stream reset output unexpected: %s", buf.String())
	}
}

func TestRunKillStatus_JSONMode(t *testing.T) {
	resp := streamStatusResponse{OrgID: "org-main", FleetID: "prod", EmergencyControlsRead: true}
	client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
	cmd, buf := newRecoveryCmd(t)

	if err := runKillStatus(cmd, killStatusOptions{client: client, orgID: "org-main", fleetID: "prod", jsonOut: true}); err != nil {
		t.Fatalf("runKillStatus --json: %v", err)
	}
	if !strings.Contains(buf.String(), `"org_id":"org-main"`) {
		t.Fatalf("json mode should emit raw JSON, got: %s", buf.String())
	}
}

func TestRunStoreDump_NonJSONFallback(t *testing.T) {
	client := newTestClientServer(t, "tok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json-body"))
	}))
	cmd, buf := newRecoveryCmd(t)

	if err := runStoreDump(cmd, storeDumpOptions{client: client, orgID: "org-main", fleetID: "prod"}); err != nil {
		t.Fatalf("runStoreDump non-JSON: %v", err)
	}
	if !strings.Contains(buf.String(), "not-json-body") {
		t.Fatalf("non-JSON fallback should print raw body, got: %s", buf.String())
	}
}

// TestRunStreamReset_FailsClosedOnUnreadableControls confirms the destructive
// reset aborts (does not report "nothing to clear") when the control plane
// cannot confirm active rollback state.
func TestRunStreamReset_FailsClosedOnUnreadableControls(t *testing.T) {
	resp := streamStatusResponse{OrgID: "org-main", FleetID: "prod", EmergencyControlsRead: false}
	client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
	cmd, _ := newRecoveryCmd(t)

	err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", fleetID: "prod", confirm: true})
	if err == nil || !strings.Contains(err.Error(), "emergency controls") {
		t.Fatalf("expected fail-closed error on unreadable controls, got %v", err)
	}
}
