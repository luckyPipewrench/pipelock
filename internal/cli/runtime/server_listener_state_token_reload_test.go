// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
)

func TestServer_Reload_ListenerRequireStateTokenUpdatesRunningListener(t *testing.T) {
	testport.WithRetry(t, 2, func(addrs []string) error {
		fetchAddr, mcpAddr := addrs[0], addrs[1]
		var upstreamCalls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalls.Add(1)
			var request struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("Decode(upstream request): %v", err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, request.ID)
		}))
		defer upstream.Close()

		// Token refusal is only observable when a principal-scoped control
		// is live. Enable chain detection at first load so later token
		// reloads are the only config change under the running listener.
		cfgPath := writeServerTestConfig(t, fmt.Sprintf(`version: 1
mode: balanced
tool_chain_detection:
  enabled: true
  action: block
  window_size: 20
  window_seconds: 60
fetch_proxy:
  listen: %q
  timeout_seconds: 5
logging:
  format: json
  output: stdout
`, fetchAddr))

		s, buf := newTestServer(t, func(o *ServerOpts) {
			o.ConfigFile = cfgPath
			o.Listen = fetchAddr
			o.ListenChanged = true
			o.MCPListen = mcpAddr
			o.MCPUpstream = upstream.URL
		})
		if s.currentMCPChainMatcher() == nil {
			t.Fatal("startup config did not create MCP chain matcher")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			errCh <- s.Start(ctx)
		}()
		defer func() {
			_ = s.Shutdown(context.Background())
			select {
			case <-errCh:
			case <-time.After(5 * time.Second):
			}
		}()

		if err := waitForPortOrCommandExitResult(mcpAddr, errCh, buf); err != nil {
			return err
		}

		allowed := postTokenlessListenerToolCall(t, mcpAddr, 1)
		if strings.Contains(allowed, "authenticated principal") {
			t.Fatalf("initial tokenless request was refused: %s", allowed)
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("initial upstream calls = %d, want 1", got)
		}

		required := true
		enabled := s.proxy.CurrentConfig().Clone()
		enabled.MCPSessionBinding.ListenerRequireStateToken = &required
		if err := reloadListenerStateToken(s, enabled); err != nil {
			t.Fatalf("enable reload: %v", err)
		}
		if !s.proxy.CurrentConfig().MCPSessionBinding.RequiresListenerStateToken() {
			t.Fatal("enable reload did not publish listener_require_state_token")
		}
		denied := postTokenlessListenerToolCall(t, mcpAddr, 2)
		if !strings.Contains(denied, "authenticated principal") {
			t.Fatalf("post-enable request was not refused: %s", denied)
		}

		unchanged := s.proxy.CurrentConfig().Clone()
		unchanged.MCPSessionBinding.ListenerRequireStateToken = &required
		if err := reloadListenerStateToken(s, unchanged); err != nil {
			t.Fatalf("unchanged reload: %v", err)
		}
		if !s.proxy.CurrentConfig().MCPSessionBinding.RequiresListenerStateToken() {
			t.Fatal("unchanged reload dropped listener_require_state_token")
		}
		stillDenied := postTokenlessListenerToolCall(t, mcpAddr, 3)
		if !strings.Contains(stillDenied, "authenticated principal") {
			t.Fatalf("reload-without-change dropped the requirement: %s", stillDenied)
		}
		if got := upstreamCalls.Load(); got != 1 {
			t.Fatalf("upstream calls after enable = %d, want 1", got)
		}

		matcher := s.currentMCPChainMatcher()
		if matcher == nil {
			t.Fatal("token-required listener lost the chain matcher")
		}
		const chainSession = "mcp-listener-token-reload"
		if got := matcher.Record(chainSession, "list_issues"); got.Matched {
			t.Fatalf("untrusted-source prefix = %+v, want no match", got)
		}
		if got := matcher.Record(chainSession, "read_private_repo"); got.Matched {
			t.Fatalf("two-step trifecta prefix = %+v, want no match", got)
		}

		unrelated := s.proxy.CurrentConfig().Clone()
		unrelated.MCPSessionBinding.ListenerRequireStateToken = &required
		unrelated.ToolChainDetection.WindowSize = 30
		if err := reloadListenerStateToken(s, unrelated); err != nil {
			t.Fatalf("unrelated reload: %v", err)
		}
		if !s.proxy.CurrentConfig().MCPSessionBinding.RequiresListenerStateToken() {
			t.Fatal("unrelated reload dropped listener_require_state_token")
		}
		if s.proxy.CurrentConfig().ToolChainDetection.WindowSize != 30 {
			t.Fatal("unrelated reload did not apply tool_chain_detection.window_size")
		}
		if got := s.currentMCPChainMatcher(); got != matcher {
			t.Fatal("unrelated reload replaced the chain matcher")
		}
		if got := matcher.Record(chainSession, "create_pull_request"); !got.Matched || got.PatternName != "lethal-trifecta" {
			t.Fatalf("chain state after unrelated reload = %+v, want preserved lethal trifecta", got)
		}
		unrelatedDenied := postTokenlessListenerToolCall(t, mcpAddr, 4)
		if !strings.Contains(unrelatedDenied, "authenticated principal") {
			t.Fatalf("unrelated reload dropped the token requirement: %s", unrelatedDenied)
		}

		compat := false
		disabled := s.proxy.CurrentConfig().Clone()
		disabled.MCPSessionBinding.ListenerRequireStateToken = &compat
		if err := reloadListenerStateToken(s, disabled); err != nil {
			t.Fatalf("disable reload: %v", err)
		}
		if s.proxy.CurrentConfig().MCPSessionBinding.RequiresListenerStateToken() {
			t.Fatal("disable reload left listener_require_state_token required")
		}
		restored := postTokenlessListenerToolCall(t, mcpAddr, 5)
		if strings.Contains(restored, "authenticated principal") {
			t.Fatalf("post-disable request was refused: %s", restored)
		}
		if got := upstreamCalls.Load(); got != 2 {
			t.Fatalf("upstream calls after disable = %d, want 2", got)
		}
		return nil
	})
}

func reloadListenerStateToken(s *Server, cfg *config.Config) error {
	s.stateMu.Lock()
	s.lastReloadAt = time.Time{}
	s.stateMu.Unlock()
	return s.Reload(cfg)
}

func postTokenlessListenerToolCall(t *testing.T, addr string, id int) string {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/input"}}}`, id)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(payload)
}
