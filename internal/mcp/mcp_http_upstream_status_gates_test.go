// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

func TestUpstreamClientErrorWriteState(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "active"
		if revoked {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			state := newMCPListenerTransientState()
			if revoked {
				state.revoke()
			}
			w := httptest.NewRecorder()
			reply := upstreamClientError{status: http.StatusUnauthorized, header: http.Header{"Www-Authenticate": {upstreamStatusChallenge}}, body: []byte("refusal")}
			ok, reason := reply.writeIfActive(w, state, MCPProxyOpts{})
			if ok == revoked {
				t.Fatalf("write allowed=%v revoked=%v reason=%s", ok, revoked, reason)
			}
			if revoked {
				if w.Body.Len() != 0 || len(w.Header()) != 0 {
					t.Fatalf("revoked state wrote upstream content: %v %s", w.Header(), w.Body.String())
				}
			} else if w.Code != http.StatusUnauthorized || w.Body.String() != "refusal" || w.Header().Get("Www-Authenticate") != upstreamStatusChallenge {
				t.Fatalf("active state did not relay: %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		})
	}
}

func TestHTTPListener_ClientErrorHonorsLiveResponseGates(t *testing.T) {
	for _, gate := range []string{"identity", "kill switch"} {
		for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
			t.Run(gate+"/"+method, func(t *testing.T) {
				var changed atomic.Bool
				cfg := config.Defaults()
				ks := killswitch.New(cfg)
				const replyText = "upstream refusal after revocation"
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					changed.Store(true)
					if gate == "kill switch" {
						ks.SetAPI(true)
					}
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, replyText)
				}))
				t.Cleanup(upstream.Close)
				baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
					Scanner: testScannerForHTTP(t), KillSwitch: ks,
					ServerIdentityFn: func() ServerIdentity {
						if gate == "identity" && changed.Load() {
							return ServerIdentity{Refusal: identityRefusalText}
						}
						return ServerIdentity{Name: "vendor-indexer", PolicyName: "vendor-indexer", Binding: "binding", BindingMode: config.MCPAckBindingModeVerifiedLocalSession, Revision: "rev"}
					},
				})
				request := ""
				if method == http.MethodPost {
					request = upstreamStatusInitialize
				}
				header := http.Header{"Accept": {"text/event-stream"}}
				resp, body := doListenerRequest(t, method, baseURL+"/", request, header)
				if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), replyText) {
					t.Fatalf("revoked upstream content relayed: status=%d body=%s", resp.StatusCode, body)
				}
			})
		}
	}
}
