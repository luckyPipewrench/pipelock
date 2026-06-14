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

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

func TestRunRollbackClear_HappyPath(t *testing.T) {
	// Set up a test server with a real rollback authorization published.
	opts := newRollbackRig(t, 0)
	cmd, _ := rollbackCobra(t)
	if err := runRollback(cmd, opts); err != nil {
		t.Fatalf("initial rollback: %v", err)
	}

	// Clear the rollback authorization via the test server's DELETE endpoint.
	srv := opts.transport.(*testServer)
	delBody, err := deleteRollbackViaTestServer(t, srv, "rollback-42-to-41-100")
	if err != nil {
		t.Fatalf("clear rollback: %v", err)
	}
	if !strings.Contains(string(delBody), `"cleared":true`) {
		t.Fatalf("clear response missing cleared=true: %s", string(delBody))
	}
}

func TestRunRollbackClear_NotFoundReturns404(t *testing.T) {
	opts := newRollbackRig(t, 0)
	srv := opts.transport.(*testServer)
	_, err := deleteRollbackViaTestServer(t, srv, "nonexistent-id")
	if err == nil {
		t.Fatal("clear nonexistent = nil error, want 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error = %v, want status 404", err)
	}
}

func TestRunRollbackClear_MissingConfirmRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runRollbackClear(cmd, rollbackClearOptions{
		authorizationID: "some-id",
		confirm:         false,
	})
	if err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("missing confirm error = %v, want --confirm required", err)
	}
}

func TestRunRollbackClear_MissingAuthorizationIDRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runRollbackClear(cmd, rollbackClearOptions{
		authorizationID: "",
		confirm:         true,
	})
	if err == nil || !strings.Contains(err.Error(), "--authorization-id is required") {
		t.Fatalf("missing authorization-id error = %v, want required", err)
	}
}

func TestRollbackClearCmd_NoFleetLicenseFailsClosed(t *testing.T) {
	t.Setenv(license.EnvLicenseKey, "")
	t.Setenv(license.EnvLicensePublicKey, "")
	t.Setenv(license.EnvLicenseCRLFile, "")
	cmd := Cmd()
	cmd.SetArgs([]string{
		"rollback", "clear", "--authorization-id", "some-id", "--confirm",
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil || !errors.Is(err, license.ErrFleetLicenseRequired) {
		t.Fatalf("rollback clear without license error = %v, want ErrFleetLicenseRequired", err)
	}
}

// deleteRollbackViaTestServer sends a DELETE to the test server's rollback
// authorizations endpoint and returns the response body.
func deleteRollbackViaTestServer(t *testing.T, srv *testServer, authorizationID string) ([]byte, error) {
	t.Helper()
	return deleteJSONViaTestServer(t, srv, controlplane.RollbackAuthorizationsPath, map[string]string{
		"authorization_id": authorizationID,
	})
}

func deleteJSONViaTestServer(t *testing.T, srv *testServer, path string, body any) ([]byte, error) {
	t.Helper()
	payload, err := encodeJSON(body)
	if err != nil {
		t.Fatalf("marshal delete body: %v", err)
	}
	ctx := context.Background()
	req, err := newTestDeleteRequest(ctx, srv.url+path, payload, testAdminToken)
	if err != nil {
		t.Fatalf("build delete request: %v", err)
	}
	resp, err := srv.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("conductor returned status " + resp.Status)
	}
	return buf.Bytes(), nil
}
