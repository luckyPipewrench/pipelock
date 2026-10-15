// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestCardJSONRequestTransports(t *testing.T) {
	card := "41111111" + "11111111"
	metric := `{"n":0.` + card + `}`
	cardString := `{"n":"` + card + `"}`
	for _, surface := range []string{"stdio", "http bridge JSON", "http bridge SSE", "http listener JSON", "http listener SSE", "websocket"} {
		for _, redaction := range []bool{false, true} {
			for _, tt := range []struct {
				name, args string
				clean      bool
			}{
				{"metric", metric, true},
				{"integer component", `{"n":-` + card + `.1}`, false},
				{"written exponent", `{"n":` + card + `e-2}`, false},
				{"card string", cardString, false},
				{"encoded card", `{"n":"` + base64.StdEncoding.EncodeToString([]byte(card)) + `"}`, false},
			} {
				mode := "block"
				if redaction {
					mode = "redact"
				}
				t.Run(surface+"/"+mode+"/"+tt.name, func(t *testing.T) {
					cfg := config.Defaults()
					cfg.Internal = nil
					cfg.DLP.ScanEnv = false
					sc := scanner.MustNew(cfg)
					t.Cleanup(sc.Close)
					opts := testOpts(sc)
					opts.InputCfg = &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock}
					if redaction {
						opts.InputCfg.Action = config.ActionWarn
						opts.RedactMatcher = redact.NewDefaultMatcher()
						opts.RedactLimits = redact.DefaultLimits().ToLimits()
					}
					// The existing redactor marshals object keys in sorted order.
					// Use that order so exact-byte assertions check numeric spelling
					// and forwarding without imposing an object-order contract.
					request := `{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":` + tt.args + `,"name":"metrics"}}`
					want := ""
					if tt.clean {
						want = request
					} else if redaction && tt.args == cardString {
						want = strings.Replace(request, card, "<pl:credit-card:1>", 1)
					}
					// Encoded cards are detected but aren't rewritten by this matcher.
					// Block them via the configured scanner in both test modes.
					if tt.name == "encoded card" {
						opts.InputCfg.Action = config.ActionBlock
					}
					output := runCardRequestTransport(t, surface, request, want, opts)
					if want == "" && !strings.Contains(output, "-32001") {
						t.Fatalf("missing input block result: %s", output)
					}
				})
			}
		}
	}
}

func runCardRequestTransport(t *testing.T, surface, request, want string, opts MCPProxyOpts) string {
	t.Helper()
	if surface == "stdio" {
		if runtime.GOOS == osWindows {
			t.Skip("recording subprocess fixture requires Unix")
		}
		var stdout bytes.Buffer
		stderr := &syncBuffer{}
		wantLine := ""
		if want != "" {
			wantLine = want + "\n"
		}
		if err := RunProxy(t.Context(), strings.NewReader(request+"\n"), &stdout, stderr, recordingEchoCommand(t, wantLine), opts); err != nil {
			t.Fatal(err)
		}
		return stdout.String()
	}
	var received lockedHTTPBuffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if surface == "websocket" {
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				t.Errorf("upgrade: %v", err)
				return
			}
			defer func() { _ = conn.Close() }()
			if body, _, err := wsutil.ReadClientData(conn); err == nil {
				_, _ = received.Write(body)
				_ = wsutil.WriteServerMessage(conn, ws.OpText, []byte(makeResponse(1, "accepted")))
			}
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
			return
		}
		_, _ = received.Write(body)
		response := makeResponse(1, "accepted")
		if strings.HasSuffix(surface, "SSE") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+response+"\n\n")
		} else {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, response)
		}
	}))
	defer upstream.Close()
	t.Cleanup(func() {
		if got := received.String(); got != want {
			t.Errorf("upstream received %q, want %q", got, want)
		}
	})
	if strings.HasPrefix(surface, "http listener") {
		baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, baseURL+"/", strings.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	stdin, input := io.Pipe()
	defer func() { _ = input.Close() }()
	var stdout, stderr lockedHTTPBuffer
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		if surface == "websocket" {
			done <- RunWSProxy(ctx, stdin, &stdout, &stderr, wsURL(upstream), opts)
		} else {
			done <- RunHTTPProxy(ctx, stdin, &stdout, &stderr, upstream.URL, nil, opts)
		}
	}()
	if _, err := io.WriteString(input, request+"\n"); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 3*time.Second, func() bool { return stdout.contains(`"id":1`) }, "MCP request result")
	_ = input.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return stdout.String()
}
