//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	conductorcore "github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// errorStatusHandler returns the given HTTP status for every request, so the
// recovery run* funcs exercise their getStreamStatus / delete error branches.
func errorStatusHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", status)
	})
}

// invalidJSONHandler returns a 200 with a non-JSON body for GET, so the run*
// funcs that strictly decode the stream-status response hit their decode-error
// branch.
func invalidJSONHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	})
}

func TestRunStoreDump_Errors(t *testing.T) {
	t.Run("missing org id", func(t *testing.T) {
		cmd, _ := newRecoveryCmd(t)
		err := runStoreDump(cmd, storeDumpOptions{orgID: ""})
		if err == nil || !strings.Contains(err.Error(), "--org-id is required") {
			t.Fatalf("err=%v, want --org-id required", err)
		}
	})
	t.Run("client build failure", func(t *testing.T) {
		cmd, _ := newRecoveryCmd(t)
		// Empty clientOptions: newConductorClient fails on the required --server.
		err := runStoreDump(cmd, storeDumpOptions{client: clientOptions{}, orgID: "org-main"})
		if err == nil || !strings.Contains(err.Error(), "--server is required") {
			t.Fatalf("err=%v, want --server required", err)
		}
	})
	t.Run("stream status http error", func(t *testing.T) {
		client := newTestClientServer(t, "tok", errorStatusHandler(http.StatusInternalServerError))
		cmd, _ := newRecoveryCmd(t)
		err := runStoreDump(cmd, storeDumpOptions{client: client, orgID: "org-main"})
		if err == nil {
			t.Fatal("err=nil, want stream-status error")
		}
	})
}

func TestRunKillStatus_Errors(t *testing.T) {
	t.Run("client build failure", func(t *testing.T) {
		cmd, _ := newRecoveryCmd(t)
		err := runKillStatus(cmd, killStatusOptions{client: clientOptions{}, orgID: "org-main"})
		if err == nil || !strings.Contains(err.Error(), "--server is required") {
			t.Fatalf("err=%v, want --server required", err)
		}
	})
	t.Run("stream status http error", func(t *testing.T) {
		client := newTestClientServer(t, "tok", errorStatusHandler(http.StatusBadGateway))
		cmd, _ := newRecoveryCmd(t)
		err := runKillStatus(cmd, killStatusOptions{client: client, orgID: "org-main"})
		if err == nil {
			t.Fatal("err=nil, want stream-status error")
		}
	})
	t.Run("undecodable response", func(t *testing.T) {
		client := newTestClientServer(t, "tok", invalidJSONHandler())
		cmd, _ := newRecoveryCmd(t)
		err := runKillStatus(cmd, killStatusOptions{client: client, orgID: "org-main"})
		if err == nil || !strings.Contains(err.Error(), "decode stream status") {
			t.Fatalf("err=%v, want decode error", err)
		}
	})
}

func TestRunStreamReset_Errors(t *testing.T) {
	t.Run("client build failure", func(t *testing.T) {
		cmd, _ := newRecoveryCmd(t)
		err := runStreamReset(cmd, streamResetOptions{client: clientOptions{}, orgID: "org-main", confirm: true})
		if err == nil || !strings.Contains(err.Error(), "--server is required") {
			t.Fatalf("err=%v, want --server required", err)
		}
	})
	t.Run("stream status http error", func(t *testing.T) {
		client := newTestClientServer(t, "tok", errorStatusHandler(http.StatusInternalServerError))
		cmd, _ := newRecoveryCmd(t)
		err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", confirm: true})
		if err == nil {
			t.Fatal("err=nil, want stream-status error")
		}
	})
	t.Run("undecodable response", func(t *testing.T) {
		client := newTestClientServer(t, "tok", invalidJSONHandler())
		cmd, _ := newRecoveryCmd(t)
		err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", confirm: true})
		if err == nil || !strings.Contains(err.Error(), "decode stream status") {
			t.Fatalf("err=%v, want decode error", err)
		}
	})
	t.Run("no active rollbacks is a clean no-op", func(t *testing.T) {
		resp := streamStatusResponse{OrgID: "org-main", FleetID: "prod", EmergencyControlsRead: true}
		client := newTestClientServer(t, "tok", streamStatusHandler(t, resp))
		cmd, buf := newRecoveryCmd(t)
		if err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", confirm: true}); err != nil {
			t.Fatalf("runStreamReset(no active): %v", err)
		}
		if !strings.Contains(buf.String(), "no active rollback authorizations to clear") {
			t.Fatalf("output=%q, want no-active message", buf.String())
		}
	})
	t.Run("delete failure warns and continues", func(t *testing.T) {
		// GET returns one active rollback; DELETE fails. The reset must warn,
		// keep going, and report 0 of 1 cleared rather than aborting.
		resp := streamStatusResponse{
			OrgID: "org-main", FleetID: "prod", EmergencyControlsRead: true,
			ActiveRollbacks: []controlplane.ActiveRollbackAuthorization{{AuthorizationID: "auth-stuck", TargetVersion: 7}},
		}
		body, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				http.Error(w, "delete boom", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
		client := newTestClientServer(t, "tok", handler)
		cmd, buf := newRecoveryCmd(t)
		if err := runStreamReset(cmd, streamResetOptions{client: client, orgID: "org-main", confirm: true}); err != nil {
			t.Fatalf("runStreamReset(delete fail): %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "warning: failed to clear auth-stuck") {
			t.Fatalf("output=%q, want delete warning", out)
		}
		if !strings.Contains(out, "cleared 0 of 1") {
			t.Fatalf("output=%q, want cleared 0 of 1", out)
		}
	})
}

func TestAudiencesEquivalent(t *testing.T) {
	tests := []struct {
		name string
		a, b conductorcore.Audience
		want bool
	}{
		{"both empty", conductorcore.Audience{}, conductorcore.Audience{}, true},
		{
			"equal ids and labels",
			conductorcore.Audience{InstanceIDs: []string{"a", "b"}, Labels: map[string]string{"ring": "canary"}},
			conductorcore.Audience{InstanceIDs: []string{"b", "a"}, Labels: map[string]string{"ring": "canary"}},
			true,
		},
		{
			"different instance ids",
			conductorcore.Audience{InstanceIDs: []string{"a"}},
			conductorcore.Audience{InstanceIDs: []string{"b"}},
			false,
		},
		{
			"different label count",
			conductorcore.Audience{Labels: map[string]string{"ring": "canary"}},
			conductorcore.Audience{Labels: map[string]string{"ring": "canary", "tier": "1"}},
			false,
		},
		{
			"different label value",
			conductorcore.Audience{Labels: map[string]string{"ring": "canary"}},
			conductorcore.Audience{Labels: map[string]string{"ring": "stable"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := audiencesEquivalent(tt.a, tt.b); got != tt.want {
				t.Fatalf("audiencesEquivalent(%+v, %+v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// The RunE wrappers fail closed without a fleet license. These cover the
// license-verification guard on the recovery subcommands (mirrors the rollback
// clear guard test).
func TestRecoveryCommands_NoFleetLicenseFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"store dump", []string{"store", "dump", "--org-id", "org-main"}},
		{"kill status", []string{"kill", "status", "--org-id", "org-main"}},
		{"stream reset", []string{"stream", "reset", "--org-id", "org-main", "--confirm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(license.EnvLicenseKey, "")
			t.Setenv(license.EnvLicensePublicKey, "")
			t.Setenv(license.EnvLicenseCRLFile, "")
			cmd := Cmd()
			cmd.SetArgs(tc.args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
				t.Fatalf("%s without license err=%v, want ErrFleetLicenseRequired", tc.name, err)
			}
		})
	}
}
