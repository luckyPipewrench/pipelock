//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"net/http"
	"strings"
	"testing"
)

// TestRunRollbackClear_RunPaths covers runRollbackClear's own client round trip:
// the success path (build client -> DELETE -> print body), the client-build
// failure, and a non-200 DELETE response. The existing happy-path test clears
// via the test-server helper, so these are what exercise runRollbackClear end
// to end.
func TestRunRollbackClear_RunPaths(t *testing.T) {
	t.Run("success prints cleared body", func(t *testing.T) {
		client := newTestClientServer(t, "tok", streamStatusHandler(t, streamStatusResponse{}))
		cmd, buf := newRecoveryCmd(t)
		err := runRollbackClear(cmd, rollbackClearOptions{client: client, authorizationID: "auth-x", confirm: true})
		if err != nil {
			t.Fatalf("runRollbackClear: %v", err)
		}
		if !strings.Contains(buf.String(), `"cleared":true`) {
			t.Fatalf("output=%q, want cleared:true", buf.String())
		}
	})

	t.Run("client build failure", func(t *testing.T) {
		cmd, _ := newRecoveryCmd(t)
		err := runRollbackClear(cmd, rollbackClearOptions{client: clientOptions{}, authorizationID: "auth-x", confirm: true})
		if err == nil || !strings.Contains(err.Error(), "--server is required") {
			t.Fatalf("err=%v, want --server required", err)
		}
	})

	t.Run("delete http error surfaces", func(t *testing.T) {
		client := newTestClientServer(t, "tok", errorStatusHandler(http.StatusNotFound))
		cmd, _ := newRecoveryCmd(t)
		err := runRollbackClear(cmd, rollbackClearOptions{client: client, authorizationID: "auth-x", confirm: true})
		if err == nil {
			t.Fatal("err=nil, want DELETE error")
		}
	})
}
