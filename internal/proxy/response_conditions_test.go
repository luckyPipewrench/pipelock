// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestFullResponsePolicyTransports(t *testing.T) {
	for _, transport := range []string{"intercept", "forward", "reverse"} {
		for _, tc := range []struct {
			name          string
			headers       http.Header
			body          string
			unexpected304 bool
			method        string
			status        int
		}{
			{name: "stale conditional range", headers: http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"stale"`}}, body: "PART full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "bare range", headers: http.Header{"Range": {"bytes=0-3"}}, body: "PART full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "range full scan", headers: http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"stale"`}}, body: "PART hidden_instruction", method: http.MethodGet, status: http.StatusForbidden},
			{name: "conditional full scan", headers: http.Header{"If-None-Match": {`"origin"`}, "If-Modified-Since": {"Wed, 01 Oct 2025 12:00:00 GMT"}}, body: "full representation", method: http.MethodGet, status: http.StatusOK},
			{name: "conditional scan block", headers: http.Header{"If-None-Match": {`"origin"`}}, body: "hidden_instruction", method: http.MethodGet, status: http.StatusForbidden},
			{name: "unexpected not modified", unexpected304: true, method: http.MethodGet, status: http.StatusForbidden},
			{name: "unexpected not modified head", unexpected304: true, method: http.MethodHead, status: http.StatusForbidden},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				seen := make(chan http.Header, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Clone()
					w.Header().Set("ETag", `"origin"`)
					w.Header().Set("Content-Type", "application/javascript")
					w.Header().Set("Cache-Control", "public, max-age=60")
					if tc.unexpected304 || r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
						w.WriteHeader(http.StatusNotModified)
						return
					}
					if r.Header.Get("Range") != "" && r.Header.Get("If-Range") == "" {
						w.Header().Set("Content-Range", "bytes 0-3/24")
						w.WriteHeader(http.StatusPartialContent)
						_, _ = io.WriteString(w, "PART")
						return
					}
					_, _ = io.WriteString(w, tc.body)
				})
				configure := func(cfg *config.Config) {
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionBlock
					cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "full representation marker", Regex: "hidden_instruction"})
				}
				var resp *http.Response
				switch transport {
				case "intercept":
					origin := httptest.NewTLSServer(handler)
					defer origin.Close()
					cache, pool, cfg, _, logger, m := testInterceptSetup(t)
					configure(cfg)
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, origin.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp = interceptAndRequest(t, origin, cache, pool, cfg, sc, logger, m, req)
				case "reverse":
					cfg := config.Defaults()
					configure(cfg)
					proxy := reverseTestSetup(t, cfg, handler)
					req, err := http.NewRequestWithContext(t.Context(), tc.method, proxy.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp, err = proxy.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
				default:
					origin := httptest.NewServer(handler)
					defer origin.Close()
					addr, p, cleanup := setupForwardProxyWithInstance(t, configure)
					defer cleanup()
					installForwardTestDialer(p, origin.Listener.Addr().String())
					client := forwardHTTPClient(t, addr)
					defer client.CloseIdleConnections()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://api.example.com/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header = tc.headers.Clone()
					resp, err = client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != tc.status {
					t.Errorf("status=%d body=%q, want %d", resp.StatusCode, body, tc.status)
				}
				upstreamHeaders := <-seen
				for _, name := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since"} {
					if got := upstreamHeaders.Get(name); got != "" {
						t.Errorf("upstream %s=%q, want removed", name, got)
					}
				}
				if tc.status == http.StatusOK {
					if string(body) != tc.body {
						t.Errorf("body=%q, want full %q", body, tc.body)
					}
					if resp.Header.Get("ETag") != `"origin"` || resp.Header.Get("Cache-Control") != "public, max-age=60" {
						t.Fatal("origin cache policy was changed")
					}
				} else if resp.Header.Get("ETag") != "" {
					t.Fatal("unapproved origin validator released")
				}
			})
		}
	}
}

func TestFullResponsePolicyWebSocketUpgrade(t *testing.T) {
	headers := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "If-None-Match": {`"origin"`}, "Range": {"bytes=0-3"}}
	if !applyFullResponsePolicy(headers, nil) || !applyFullResponsePolicy(nil, &http.Response{StatusCode: http.StatusSwitchingProtocols}) {
		t.Fatal("WebSocket upgrade refused by full-response policy")
	}
	if headers.Get("Connection") != "Upgrade" || headers.Get("Upgrade") != "websocket" {
		t.Fatal("upgrade headers removed")
	}
	backend, closeBackend := wsEchoServer(t)
	defer closeBackend()
	addr, cleanup := setupWSProxy(t, nil)
	defer cleanup()
	conn, err := dialWSConnWithHeader(addr, backend, headers)
	if err != nil {
		t.Fatalf("WebSocket upgrade: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const message = "ordinary message"
	if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(message)); err != nil {
		t.Fatal(err)
	}
	body, op, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if op != ws.OpText || string(body) != message {
		t.Fatalf("echo=(%q,%v), want text %q", body, op, message)
	}
}

func TestForwardIncompleteResponseReceipts(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusPartialContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer origin.Close()
			addr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = true
			})
			defer cleanup()
			rph := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(rph.emitter)
			installForwardTestDialer(p, origin.Listener.Addr().String())
			client := forwardHTTPClient(t, addr)
			defer client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/asset.js", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			assertIncompleteResponseBlock(t, resp, body)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status=%d, want 403", resp.StatusCode)
			}
			pattern := string(blockreason.ResponseIncomplete)
			var foundBlock, foundOutcome bool
			for _, record := range rph.findReceipts(t) {
				if record.ActionRecord.Verdict == config.ActionBlock && record.ActionRecord.Layer == "browser_cache" && record.ActionRecord.Pattern == string(blockreason.ResponseIncomplete) {
					foundBlock = true
				}
				if record.ActionRecord.Layer == receiptOutcomeLayer && record.ActionRecord.Pattern == receiptOutcomePattern("403", -1, pattern) {
					foundOutcome = true
				}
			}
			if !foundBlock || !foundOutcome {
				t.Fatalf("missing refusal evidence: block=%v outcome=%v", foundBlock, foundOutcome)
			}
		})
	}
}

func TestFullResponsePolicyConditionalSiblings(t *testing.T) {
	const marker = "hidden_instruction"
	full := "PART " + marker
	type originObs struct {
		rangeVals []string
		ifMatch   string
		ifUnmod   string
		acceptEnc string
		method    string
	}
	for _, transport := range []string{"intercept", "forward", "reverse"} {
		for _, tc := range []struct {
			name        string
			method      string
			headers     http.Header
			mode        string
			wantStatus  int
			wantIfMatch bool
		}{
			{name: "if-match kept and full body scanned", method: http.MethodGet, headers: http.Header{"If-Match": {`"other"`}, "Range": {"bytes=0-3"}}, mode: "if-match-412", wantStatus: http.StatusForbidden, wantIfMatch: true},
			{name: "if-unmodified-since kept", method: http.MethodGet, headers: http.Header{"If-Unmodified-Since": {"Wed, 01 Oct 2025 12:00:00 GMT"}, "Range": {"bytes=0-3"}}, mode: "full-marker", wantStatus: http.StatusForbidden},
			{name: "multi range stripped", method: http.MethodGet, headers: http.Header{"Range": {"bytes=0-1", "bytes=2-3"}}, mode: "full-ok", wantStatus: http.StatusOK},
			{name: "post range stripped", method: http.MethodPost, headers: http.Header{"Range": {"bytes=0-3"}}, mode: "full-ok", wantStatus: http.StatusOK},
			{name: "head still ok", method: http.MethodHead, headers: http.Header{"If-None-Match": {`"origin"`}, "Range": {"bytes=0-3"}}, mode: "full-ok", wantStatus: http.StatusOK},
			{name: "hostile 206 clean slice", method: http.MethodGet, headers: http.Header{"Range": {"bytes=0-3"}, "If-Range": {`"stale"`}}, mode: "always-206-clean", wantStatus: http.StatusForbidden},
			{name: "hostile 206 marker slice", method: http.MethodGet, headers: http.Header{"Range": {"bytes=0-3"}}, mode: "always-206-marker", wantStatus: http.StatusForbidden},
			{name: "412 marker body", method: http.MethodGet, headers: http.Header{"If-Match": {`"nope"`}}, mode: "412-marker", wantStatus: http.StatusForbidden, wantIfMatch: true},
			{name: "416 marker body", method: http.MethodGet, headers: http.Header{"Range": {"bytes=0-3"}}, mode: "416-marker", wantStatus: http.StatusForbidden},
			{name: "gzip marker", method: http.MethodGet, headers: http.Header{"Accept-Encoding": {"gzip"}, "If-None-Match": {`"origin"`}}, mode: "gzip-marker", wantStatus: http.StatusForbidden},
			{name: "gzip partial", method: http.MethodGet, headers: http.Header{"Range": {"bytes=0-3"}}, mode: "gzip-206", wantStatus: http.StatusForbidden},
			{name: "if-match still 304", method: http.MethodGet, headers: http.Header{"If-Match": {`"origin"`}}, mode: "304-if-match", wantStatus: http.StatusForbidden, wantIfMatch: true},
			{name: "304 with body", method: http.MethodGet, headers: nil, mode: "304-body", wantStatus: http.StatusForbidden},
			{name: "vary on full", method: http.MethodGet, headers: nil, mode: "vary-ok", wantStatus: http.StatusOK},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				obs := make(chan originObs, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					obs <- originObs{
						rangeVals: append([]string(nil), r.Header.Values("Range")...),
						ifMatch:   r.Header.Get("If-Match"),
						ifUnmod:   r.Header.Get("If-Unmodified-Since"),
						acceptEnc: r.Header.Get("Accept-Encoding"),
						method:    r.Method,
					}
					w.Header().Set("Content-Type", "application/javascript")
					w.Header().Set("ETag", `"origin"`)
					w.Header().Set("Cache-Control", "public, max-age=60")
					switch tc.mode {
					case "always-206-clean":
						w.Header().Set("Content-Range", "bytes 0-3/24")
						w.Header().Set("Vary", "Accept-Encoding")
						w.WriteHeader(http.StatusPartialContent)
						_, _ = io.WriteString(w, "PART")
					case "always-206-marker":
						w.Header().Set("Content-Range", "bytes 0-20/20")
						w.WriteHeader(http.StatusPartialContent)
						_, _ = io.WriteString(w, marker)
					case "412-marker", "if-match-412":
						w.WriteHeader(http.StatusPreconditionFailed)
						_, _ = io.WriteString(w, marker)
					case "416-marker":
						w.Header().Set("Content-Range", "bytes */24")
						w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
						_, _ = io.WriteString(w, marker)
					case "gzip-marker":
						var buf bytes.Buffer
						zw := gzip.NewWriter(&buf)
						_, _ = zw.Write([]byte(marker))
						_ = zw.Close()
						w.Header().Set("Content-Encoding", "gzip")
						w.WriteHeader(http.StatusOK)
						_, _ = w.Write(buf.Bytes())
					case "gzip-206":
						var buf bytes.Buffer
						zw := gzip.NewWriter(&buf)
						_, _ = zw.Write([]byte("PART"))
						_ = zw.Close()
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("Content-Range", "bytes 0-3/24")
						w.WriteHeader(http.StatusPartialContent)
						_, _ = w.Write(buf.Bytes())
					case "304-if-match", "304-body":
						w.WriteHeader(http.StatusNotModified)
						if tc.mode == "304-body" {
							_, _ = io.WriteString(w, marker)
						}
					case "vary-ok", "full-ok":
						w.Header().Set("Vary", "Accept-Encoding")
						_, _ = io.WriteString(w, "full representation")
					default:
						_, _ = io.WriteString(w, full)
					}
				})
				configure := func(cfg *config.Config) {
					cfg.ResponseScanning.Enabled = true
					cfg.ResponseScanning.Action = config.ActionBlock
					cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: "marker", Regex: marker})
				}
				var resp *http.Response
				switch transport {
				case "intercept":
					origin := httptest.NewTLSServer(handler)
					defer origin.Close()
					cache, pool, cfg, _, logger, m := testInterceptSetup(t)
					configure(cfg)
					sc := scanner.MustNew(cfg)
					defer sc.Close()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, origin.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					if tc.headers != nil {
						req.Header = tc.headers.Clone()
					}
					resp = interceptAndRequest(t, origin, cache, pool, cfg, sc, logger, m, req)
				case "reverse":
					cfg := config.Defaults()
					configure(cfg)
					proxy := reverseTestSetup(t, cfg, handler)
					req, err := http.NewRequestWithContext(t.Context(), tc.method, proxy.URL+"/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					if tc.headers != nil {
						req.Header = tc.headers.Clone()
					}
					resp, err = proxy.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
				default:
					origin := httptest.NewServer(handler)
					defer origin.Close()
					addr, p, cleanup := setupForwardProxyWithInstance(t, configure)
					defer cleanup()
					installForwardTestDialer(p, origin.Listener.Addr().String())
					client := forwardHTTPClient(t, addr)
					defer client.CloseIdleConnections()
					req, err := http.NewRequestWithContext(t.Context(), tc.method, "http://api.example.com/asset.js", nil)
					if err != nil {
						t.Fatal(err)
					}
					if tc.headers != nil {
						req.Header = tc.headers.Clone()
					}
					resp, err = client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				seen := <-obs
				if seen.method != tc.method || seen.acceptEnc != "identity" {
					t.Errorf("upstream method/encoding = %s/%s", seen.method, seen.acceptEnc)
				}
				if seen.ifUnmod != tc.headers.Get("If-Unmodified-Since") {
					t.Error("upstream lost If-Unmodified-Since")
				}
				var parsed struct {
					Error   string `json:"error"`
					Blocked bool   `json:"blocked"`
					Reason  string `json:"block_reason"`
				}
				_ = json.Unmarshal(body, &parsed)
				refused := strings.Contains(tc.mode, "206") || strings.HasPrefix(tc.mode, "304")
				if refused {
					if !parsed.Blocked || parsed.Reason == "" || parsed.Error == "upstream unavailable" {
						t.Errorf("refusal is not a policy block: %s", body)
					}
					for _, name := range []string{"ETag", "Vary", "Content-Range", "Cache-Control", "Content-Encoding"} {
						if resp.Header.Get(name) != "" {
							t.Errorf("refusal released origin %s", name)
						}
					}
					if resp.Header.Get("X-Pipelock-Block-Reason") == "" {
						t.Error("refusal missing block metadata")
					}
				}
				if len(seen.rangeVals) != 0 {
					t.Errorf("upstream still saw %d range values", len(seen.rangeVals))
				}
				if tc.wantIfMatch && seen.ifMatch == "" {
					t.Errorf("upstream lost If-Match")
				}
				if !tc.wantIfMatch && seen.ifMatch != "" {
					t.Errorf("upstream saw If-Match")
				}
				if strings.Contains(string(body), marker) {
					t.Errorf("client body contains the unscanned marker")
				}
				if tc.wantStatus != 0 && resp.StatusCode != tc.wantStatus {
					t.Errorf("status=%d want %d", resp.StatusCode, tc.wantStatus)
				}
			})
		}
	}
}

func TestReverseIncompleteResponseReceipts(t *testing.T) {
	for _, status := range []int{http.StatusNotModified, http.StatusPartialContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cfg := reverseTestConfig()
			cfg.FlightRecorder.RequireReceipts = true
			proxySrv, dir, closeRec := reverseReceiptParitySetup(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxySrv.URL+"/asset.js", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := proxySrv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status=%d, want 403", resp.StatusCode)
			}
			waitForReverseOutcomeReceipt(t, dir)
			closeRec()
			records := extractReceiptsFromDir(t, dir)
			block := findReceiptByLayer(t, records, "browser_cache")
			pattern := string(blockreason.ResponseIncomplete)
			if block.ActionRecord.Verdict != config.ActionBlock || block.ActionRecord.Pattern != pattern {
				t.Fatalf("wrong refusal receipt: %+v", block.ActionRecord)
			}
			assertReverseIntentOutcomePair(t, records, "status=403", "reason="+pattern)
		})
	}
}
