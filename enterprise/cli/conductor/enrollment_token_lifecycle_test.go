//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"net/http"
	"strings"
	"testing"
)

// fakeEnrollmentTokensHandler serves a canned enrollment-tokens list/revoke
// response so the CLI render path can be exercised without a real Conductor. It
// echoes the method and path for assertions.
func fakeEnrollmentTokensHandler(t *testing.T, listJSON, revokeJSON string) (http.Handler, *string, *string) {
	t.Helper()
	var gotMethod, gotPath string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodDelete:
			_, _ = w.Write([]byte(revokeJSON))
		default:
			_, _ = w.Write([]byte(listJSON))
		}
	})
	return h, &gotMethod, &gotPath
}

func TestRunEnrollmentTokenList_RendersTable(t *testing.T) {
	listJSON := `{"tokens":[{"token_id":"t-1","org_id":"org-main","fleet_id":"prod","instance_id":"pl-1","environment":"prod","state":"pending","created_at":"2026-05-24T12:00:00Z","expires_at":"2026-05-24T13:00:00Z"}],"count":1}`
	handler, _, gotPath := fakeEnrollmentTokensHandler(t, listJSON, "")
	clientOpts := newTestClientServer(t, "admin-token", handler)
	cmd, out, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenList(cmd, enrollmentTokenReadOptions{client: clientOpts, orgID: "org-main"}); err != nil {
		t.Fatalf("list error = %v", err)
	}
	if !strings.Contains(out.String(), "t-1") || !strings.Contains(out.String(), "pending") {
		t.Fatalf("list output missing token metadata: %q", out.String())
	}
	if !strings.Contains(*gotPath, "org_id=org-main") {
		t.Fatalf("list path = %q, want org_id filter", *gotPath)
	}
	// The secret-bearing fields must never be requested or rendered.
	if strings.Contains(out.String(), "token_hash") || strings.Contains(out.String(), "pl_enroll_") {
		t.Fatalf("list output leaked a secret-shaped value: %q", out.String())
	}
}

func TestRunEnrollmentTokenStatus_RequiresTokenID(t *testing.T) {
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenStatus(cmd, enrollmentTokenReadOptions{})
	if err == nil || !strings.Contains(err.Error(), "--token-id is required") {
		t.Fatalf("status without token-id error = %v, want required", err)
	}
}

func TestRunEnrollmentTokenStatus_NotFoundIsError(t *testing.T) {
	handler, _, _ := fakeEnrollmentTokensHandler(t, `{"tokens":[],"count":0}`, "")
	clientOpts := newTestClientServer(t, "admin-token", handler)
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenStatus(cmd, enrollmentTokenReadOptions{client: clientOpts, tokenID: "missing"})
	if err == nil || !strings.Contains(err.Error(), "no enrollment token found") {
		t.Fatalf("status not-found error = %v, want not-found message", err)
	}
}

func TestRunEnrollmentTokenRevoke_ReportsState(t *testing.T) {
	revokeJSON := `{"token_id":"t-1","org_id":"org-main","fleet_id":"prod","instance_id":"pl-1","environment":"prod","state":"revoked","created_at":"2026-05-24T12:00:00Z","expires_at":"2026-05-24T13:00:00Z","revoked_at":"2026-05-24T12:30:00Z"}`
	handler, gotMethod, _ := fakeEnrollmentTokensHandler(t, "", revokeJSON)
	clientOpts := newTestClientServer(t, "admin-token", handler)
	cmd, out, _ := enrollmentCobra(t)
	if err := runEnrollmentTokenRevoke(cmd, enrollmentTokenReadOptions{client: clientOpts, tokenID: "t-1"}); err != nil {
		t.Fatalf("revoke error = %v", err)
	}
	if *gotMethod != http.MethodDelete {
		t.Fatalf("revoke method = %q, want DELETE", *gotMethod)
	}
	if !strings.Contains(out.String(), "revoked") || !strings.Contains(out.String(), "t-1") {
		t.Fatalf("revoke output = %q, want revoked state for t-1", out.String())
	}
}

func TestRunEnrollmentTokenRevoke_RequiresTokenID(t *testing.T) {
	cmd, _, _ := enrollmentCobra(t)
	err := runEnrollmentTokenRevoke(cmd, enrollmentTokenReadOptions{})
	if err == nil || !strings.Contains(err.Error(), "--token-id is required") {
		t.Fatalf("revoke without token-id error = %v, want required", err)
	}
}

func TestEnrollmentTokenCmd_LifecycleSubcommandsRegistered(t *testing.T) {
	cmd := Cmd()
	want := map[string]bool{"mint": false, "list": false, "status": false, "revoke": false}
	for _, c := range cmd.Commands() {
		if c.Name() != "enrollment-token" {
			continue
		}
		for _, sc := range c.Commands() {
			if _, ok := want[sc.Name()]; ok {
				want[sc.Name()] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("enrollment-token missing %q subcommand", name)
		}
	}
}
