// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
)

func TestSSHPublicKeyScanAPI(t *testing.T) {
	h := newTestHandler(t)
	h.policyCfg = policy.New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: policy.DefaultToolPolicyRules()})
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/home/u/.ssh/id_ed25519.pub", DecisionAllow},
		{"/home/u/.ssh/id_ed25519", DecisionDeny},
	} {
		t.Run(tc.path, func(t *testing.T) {
			body := `{"kind":"tool_call","input":{"tool_name":"read_file","arguments":{"path":"` + tc.path + `"}}}`
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scan", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK || resp.Decision != tc.want {
				t.Fatalf("status=%d response=%s want=%s", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}
