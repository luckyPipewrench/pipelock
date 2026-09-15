// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestServerReloadToolPoisonSnapshotAfterConcurrentRequest(t *testing.T) {
	for _, testCase := range []struct {
		name                string
		requestDuringReload bool
		removeBundle        bool
	}{
		{name: "uncontended_control"},
		{name: "request_during_publication", requestDuringReload: true},
		{name: "removal_uncontended_control", removeBundle: true},
		{name: "removal_request_during_publication", requestDuringReload: true, removeBundle: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			xdgDataHome := t.TempDir()
			t.Setenv("XDG_DATA_HOME", xdgDataHome)
			testport.WithRetry(t, 2, func(addrs []string) error {
				var bundleDir string
				wantInitialPatterns, wantFinalPatterns := 0, 1
				if testCase.removeBundle {
					bundleDir = installServerTestToolPoisonBundle(t, xdgDataHome)
					wantInitialPatterns, wantFinalPatterns = 1, 0
				}
				fetchAddr, mcpAddr := addrs[0], addrs[1]
				var upstreamCalls atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreamCalls.Add(1)
					var request struct {
						ID int `json:"id"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Errorf("decode upstream request: %v", err)
						return
					}
					description := "test-tool-poison"
					if request.ID == 4 {
						description = "Look up public documentation"
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"lookup","description":%q,"inputSchema":{"type":"object"}}]}}`, request.ID, description)
				}))
				defer upstream.Close()

				cfgPath := writeServerTestConfig(t, fmt.Sprintf(`version: 1
mode: balanced
mcp_tool_scanning:
  enabled: true
  action: block
  detect_drift: false
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
				ctx, cancel := context.WithCancel(context.Background())
				errCh := make(chan error, 1)
				go func() { errCh <- s.Start(ctx) }()
				defer func() {
					cancel()
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), testwait.Deadline(5*time.Second))
					defer shutdownCancel()
					_ = s.Shutdown(shutdownCtx)
					select {
					case <-errCh:
					case <-shutdownCtx.Done():
						t.Error("listener did not stop after cancellation")
					}
				}()
				if err := waitForPortOrCommandExitResult(mcpAddr, errCh, buf); err != nil {
					return err
				}

				if got := s.currentMCPToolExtraPoison(); len(got) != wantInitialPatterns {
					t.Fatalf("initial bundle patterns = %d, want %d", len(got), wantInitialPatterns)
				}
				initial := postReloadSnapshotToolsList(t, mcpAddr, 1)
				assertReloadSnapshotToolResponse(t, initial, testCase.removeBundle)

				if testCase.removeBundle {
					// Move this test's bundle outside the loader's discovery path.
					if err := os.Rename(bundleDir, filepath.Join(t.TempDir(), "removed-bundle")); err != nil {
						t.Fatal(err)
					}
				} else {
					installServerTestToolPoisonBundle(t, xdgDataHome)
				}
				paused := make(chan struct{})
				release := make(chan struct{})
				var releaseOnce sync.Once
				unpause := func() { releaseOnce.Do(func() { close(release) }) }
				restore := setReloadAfterProxySwapHookForTest(func(*Server) {
					close(paused)
					<-release
				})
				var reloader sync.WaitGroup
				defer func() {
					unpause()
					reloader.Wait()
					restore()
				}()
				next, err := config.Load(cfgPath)
				if err != nil {
					t.Fatal(err)
				}
				// Exercise the existing operator-approved removal path.
				next.Rules.AllowDegraded = testCase.removeBundle
				reloadDone := make(chan error, 1)
				reloader.Add(1)
				go func() {
					defer reloader.Done()
					reloadDone <- s.Reload(next)
				}()
				testwait.For(t, 5*time.Second, func() bool {
					select {
					case <-paused:
						return true
					case err := <-reloadDone:
						t.Fatalf("reload returned before publication hook: %v", err)
					default:
					}
					return false
				}, "reload to publish proxy config")
				if testCase.requestDuringReload {
					_ = postReloadSnapshotToolsList(t, mcpAddr, 2)
				}
				unpause()
				select {
				case err := <-reloadDone:
					if err != nil {
						t.Fatalf("reload: %v", err)
					}
				case <-time.After(testwait.Deadline(5 * time.Second)):
					t.Fatal("reload did not finish")
				}
				if got := s.currentMCPToolExtraPoison(); len(got) != wantFinalPatterns {
					t.Fatalf("active bundle patterns = %d, want %d", len(got), wantFinalPatterns)
				}
				result := postReloadSnapshotToolsList(t, mcpAddr, 3)
				assertReloadSnapshotToolResponse(t, result, !testCase.removeBundle)
				benign := postReloadSnapshotToolsList(t, mcpAddr, 4)
				if !strings.Contains(benign, `"description":"Look up public documentation"`) {
					t.Fatalf("new bundle rule refused the benign response: %s", benign)
				}
				wantCalls := int32(3)
				if testCase.requestDuringReload {
					wantCalls++
				}
				if got := upstreamCalls.Load(); got != wantCalls {
					t.Fatalf("upstream calls = %d, want %d", got, wantCalls)
				}
				return nil
			})
		})
	}
}

func assertReloadSnapshotToolResponse(t *testing.T, result string, wantBlocked bool) {
	t.Helper()
	var response struct {
		Error json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(result), &response); err != nil {
		t.Fatalf("decode response: %v: %s", err, result)
	}
	blocked := len(response.Error) > 0 && string(response.Error) != "null"
	if blocked != wantBlocked {
		t.Fatalf("tool response blocked = %v, want %v: %s", blocked, wantBlocked, result)
	}
	if !wantBlocked && !strings.Contains(result, `"description":"test-tool-poison"`) {
		t.Fatalf("allowed response omitted the upstream tool: %s", result)
	}
}

func postReloadSnapshotToolsList(t *testing.T, addr string, id int) string {
	t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, id)
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(5*time.Second))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
