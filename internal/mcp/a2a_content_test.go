// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func a2aContentBody(t *testing.T, field, text string) []byte {
	t.Helper()
	var body any
	switch field {
	case "key":
		body = map[string]any{text: nil}
	case "nested_key":
		body = map[string]any{"items": []any{map[string]any{text: map[string]any{}}}}
	case "root":
		body = text
	case "array":
		body = []any{text}
	default:
		body = map[string]any{field: text}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestA2AContentEveryFieldAndKey(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionBlock
	for _, field := range []string{"text", "token", "secret", "api_key", "PASSWORD", "credentials", "key", "nested_key", "root", "array"} {
		for _, benign := range []bool{false, true} {
			name := field + "/injection"
			text := a2aDepthInjection
			if benign {
				name, text = field+"/benign", "hello from a peer"
			}
			t.Run(name, func(t *testing.T) {
				body := a2aContentBody(t, field, text)
				for _, result := range []A2AScanResult{
					ScanA2ARequestBody(t.Context(), body, sc, cfg),
					ScanA2AResponseBody(t.Context(), body, sc, cfg),
				} {
					if benign {
						if !result.Clean {
							t.Fatalf("ordinary content must pass: %+v", result)
						}
					} else if result.Clean || result.Action != config.ActionBlock || len(result.InjectFindings) == 0 || len(result.DLPFindings) != 0 || len(result.URLFindings) != 0 {
						t.Fatalf("content must retain its injection classification: %+v", result)
					}
				}
			})
		}
	}
}

func TestA2AURLContentInjectionClassification(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionBlock
	for _, field := range []string{"url", "key"} {
		t.Run(field, func(t *testing.T) {
			for _, benign := range []bool{false, true} {
				text := "https://api.vendor.example/" + a2aDepthInjection
				if benign {
					text = "https://api.vendor.example/reference"
				}
				body := a2aContentBody(t, field, text)
				for _, result := range []A2AScanResult{
					ScanA2ARequestBody(t.Context(), body, sc, cfg),
					ScanA2AResponseBody(t.Context(), body, sc, cfg),
				} {
					if result.Clean != benign || !benign && (result.Action != config.ActionBlock || len(result.InjectFindings) == 0) {
						t.Fatalf("URL content must retain injection classification: benign=%t result=%+v", benign, result)
					}
				}
			}
		})
	}
}

func TestA2AResponseContentTransportParity(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionBlock)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	opts := MCPProxyOpts{Scanner: sc, A2ACfg: cfg}
	for _, surface := range []string{"dispatcher", "stdio", "listener", "upstream", "listener_sse", "upstream_sse"} {
		for _, field := range []string{"text", "token", "secret", "api_key", "PASSWORD", "key", "nested_key"} {
			for _, benign := range []bool{false, true} {
				name, text := "injection", a2aDepthInjection
				if benign {
					name, text = "benign", "hello from a peer"
				}
				t.Run(surface+"/"+field+"/"+name, func(t *testing.T) {
					line := `{"jsonrpc":"2.0","id":1,"result":` + string(a2aContentBody(t, field, text)) + `}`
					if surface == "dispatcher" {
						verdict := ScanResponseA2A([]byte(line), sc, &A2AResponseOpts{Cfg: cfg, Method: "SendMessage"})
						if benign {
							if !verdict.Clean {
								t.Fatalf("ordinary response must pass: %+v", verdict)
							}
						} else if verdict.Clean || verdict.Action != config.ActionBlock || len(verdict.Matches) == 0 || len(verdict.DLPMatches) != 0 {
							t.Fatalf("response content must block with injection findings: %+v", verdict)
						}
						return
					}
					var got []byte
					if surface == "stdio" {
						tracker := NewRequestTracker()
						tracker.TrackRequest(json.RawMessage(`1`), "SendMessage")
						out, _, found := forwardA2AResponseTracked(t, line, opts, tracker)
						if found == benign {
							t.Fatalf("finding=%t benign=%t", found, benign)
						}
						got = []byte(out)
					} else {
						contentType := "application/json"
						if strings.HasSuffix(surface, "_sse") {
							contentType, line = "text/event-stream", "data: "+line+"\n\n"
						}
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							w.Header().Set("Content-Type", contentType)
							_, _ = io.WriteString(w, line)
						}))
						t.Cleanup(upstream.Close)
						got, _ = driveA2AHTTPDepth(t, upstream.URL, `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}`, opts, strings.TrimSuffix(surface, "_sse"))
					}
					assertA2AContentResponse(t, got, benign)
				})
			}
		}
	}
}

func TestA2AContentInspectionState(t *testing.T) {
	for _, responseLayer := range []bool{false, true} {
		scannerCfg := config.Defaults()
		scannerCfg.Internal = nil
		scannerCfg.ResponseScanning.Enabled = responseLayer
		scannerCfg.ResponseScanning.Action = config.ActionBlock
		sc := scanner.MustNew(scannerCfg)
		t.Cleanup(sc.Close)
		cfg := enabledA2ACfg()
		cfg.Action = config.ActionWarn
		for _, field := range []string{"token", "key", "nested_key"} {
			for _, text := range []string{"hello from a peer", a2aDepthInjection, "hello from a peer", a2aDepthInjection} {
				body := a2aContentBody(t, field, text)
				line := `{"jsonrpc":"2.0","id":1,"result":` + string(body) + `}`
				verdict := ScanResponseA2A([]byte(line), sc, &A2AResponseOpts{Cfg: cfg, Method: "SendMessage"})
				benign := text != a2aDepthInjection
				if verdict.Clean != benign || !benign && (verdict.Action != config.ActionBlock || len(verdict.Matches) == 0) {
					t.Fatalf("each scan must inspect current content: response_layer=%t field=%s benign=%t verdict=%+v", responseLayer, field, benign, verdict)
				}
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		body := a2aContentBody(t, "token", "hello from a peer")
		for _, result := range []A2AScanResult{
			ScanA2ARequestBody(ctx, body, sc, cfg),
			ScanA2AResponseBody(ctx, body, sc, cfg),
		} {
			verdict := a2aScanToVerdict(json.RawMessage(`1`), result)
			if result.Clean || result.ScanError == "" || verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error == "" {
				t.Fatalf("incomplete inspection must block: result=%+v verdict=%+v", result, verdict)
			}
		}
	}
}

func assertA2AContentResponse(t *testing.T, got []byte, benign bool) {
	t.Helper()
	if benign {
		if !bytes.Contains(got, []byte(`"result"`)) || bytes.Contains(got, []byte(`"error"`)) {
			t.Fatalf("ordinary content must be forwarded: %.300s", got)
		}
	} else if bytes.Contains(got, []byte(`"result"`)) || !bytes.Contains(got, []byte(`"error"`)) || !bytes.Contains(got, []byte("pipelock")) {
		t.Fatalf("response content must be withheld: %.300s", got)
	}
}

func TestA2ARequestContentTransportParity(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionBlock
	opts := MCPProxyOpts{Scanner: sc, A2ACfg: cfg}
	for _, surface := range []string{"stdio", "listener", "upstream"} {
		for _, field := range []string{"token", "key", "nested_key"} {
			for _, benign := range []bool{false, true} {
				name, text := "injection", a2aDepthInjection
				if benign {
					name, text = "benign", "hello from a peer"
				}
				t.Run(surface+"/"+field+"/"+name, func(t *testing.T) {
					request := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":` + string(a2aContentBody(t, field, text)) + `}`
					if surface == "stdio" {
						var forwarded bytes.Buffer
						blocked := make(chan BlockedRequest, 1)
						ForwardScannedInput(transport.NewStdioReader(strings.NewReader(request+"\n")), transport.NewStdioWriter(&forwarded), io.Discard, config.ActionWarn, config.ActionBlock, blocked, nil, nil, opts)
						if benign {
							if forwarded.Len() == 0 || len(blocked) != 0 {
								t.Fatalf("ordinary request must pass: forwarded=%s blocked=%d", &forwarded, len(blocked))
							}
						} else if forwarded.Len() != 0 || len(blocked) != 1 {
							t.Fatalf("request content must block: forwarded=%s blocked=%d", &forwarded, len(blocked))
						}
						return
					}
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"text":"hello"}}`)
					}))
					t.Cleanup(upstream.Close)
					got, _ := driveA2AHTTPDepth(t, upstream.URL, request, opts, surface)
					assertA2AContentResponse(t, got, benign)
				})
			}
		}
	}
}

func TestA2AContentTypedDLPVerdict(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	for _, mixed := range []bool{false, true} {
		body := `{"jsonrpc":"2.0","id":1,"result":{"token":"` + "AKIA" + "IOSFODNN7EXAMPLE" + `"`
		if mixed {
			body += `,"text":"` + a2aDepthInjection + `"`
		}
		body += `}}`
		result := ScanA2AResponseBody(t.Context(), []byte(body), sc, cfg)
		verdict := ScanResponseA2A([]byte(body), sc, &A2AResponseOpts{Cfg: cfg, Method: "SendMessage"})
		if result.Clean || verdict.Clean || verdict.Action != config.ActionBlock || len(result.DLPFindings) == 0 || !reflect.DeepEqual(verdict.DLPMatches, result.DLPFindings) {
			t.Fatalf("typed DLP findings must survive conversion: result=%+v verdict=%+v", result, verdict)
		}
		if (len(result.InjectFindings) > 0) != mixed {
			t.Fatalf("injection findings must retain their classification: %+v", result)
		}
		if !reflect.DeepEqual(verdict.Matches, result.InjectFindings) {
			t.Fatalf("only injection findings belong in response matches: %+v", verdict)
		}
	}
}

func TestA2ACardContentTypedDLPVerdict(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	for _, mixed := range []bool{false, true} {
		text := "AKIA" + "IOSFODNN7EXAMPLE"
		body := `{"jsonrpc":"2.0","id":1,"result":{"skills":[],"supportedInterfaces":[],"metadata":{"token":"` + text + `"`
		if mixed {
			body += `,"text":"` + a2aDepthInjection + `"`
		}
		body += `}}}`
		for _, method := range []string{"GetExtendedAgentCard", ""} {
			baseline := NewCardBaseline(4)
			verdict := ScanResponseA2A([]byte(body), sc, &A2AResponseOpts{Cfg: cfg, Method: method, Baseline: baseline})
			if verdict.Clean || verdict.Action != config.ActionBlock || len(verdict.DLPMatches) == 0 || len(baseline.entries) != 0 {
				t.Fatalf("card content must retain typed DLP findings: method=%q verdict=%+v baselines=%d", method, verdict, len(baseline.entries))
			}
			if (len(verdict.Matches) > 0) != mixed {
				t.Fatalf("card content must retain injection classification: mixed=%t verdict=%+v", mixed, verdict)
			}
		}
	}
}

func TestA2ACardContentEveryFieldAndKey(t *testing.T) {
	sc := testScannerWithAction(t, config.ActionBlock)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	for _, field := range []string{"token", "key", "nested_key"} {
		t.Run(field, func(t *testing.T) {
			for _, benign := range []bool{false, true} {
				text := a2aDepthInjection
				if benign {
					text = "hello from a peer"
				}
				body := `{"jsonrpc":"2.0","id":1,"result":{"skills":[],"supportedInterfaces":[],"metadata":` + string(a2aContentBody(t, field, text)) + `}}`
				for _, method := range []string{"GetExtendedAgentCard", ""} {
					baseline := NewCardBaseline(4)
					verdict := ScanResponseA2A([]byte(body), sc, &A2AResponseOpts{Cfg: cfg, Method: method, Baseline: baseline})
					if verdict.Clean != benign || !benign && (verdict.Action != config.ActionBlock || len(verdict.Matches) == 0 || len(baseline.entries) != 0) {
						t.Fatalf("card content must retain response inspection: benign=%t verdict=%+v baselines=%d", benign, verdict, len(baseline.entries))
					}
				}
			}
		})
	}
}

func TestA2AStreamContentEveryFieldAndKey(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	for _, field := range []string{"token", "key", "nested_key"} {
		for _, benign := range []bool{false, true} {
			text := a2aDepthInjection
			if benign {
				text = "hello from a peer"
			}
			body := a2aContentBody(t, field, text)
			w := httptest.NewRecorder()
			err := ScanA2AStream(t.Context(), strings.NewReader("data: "+string(body)+"\n\n"), w, w, sc, cfg)
			if benign {
				if err != nil || !bytes.Contains(w.Body.Bytes(), body) {
					t.Fatalf("ordinary stream content must pass: err=%v body=%s", err, w.Body.String())
				}
			} else if !errors.Is(err, ErrA2AStreamFinding) || w.Body.Len() != 0 {
				t.Fatalf("stream content must be withheld: err=%v body=%s", err, w.Body.String())
			}
		}
	}
}

func TestA2AStreamProtocolFindingAction(t *testing.T) {
	scannerCfg := config.Defaults()
	scannerCfg.Internal = nil
	scannerCfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
	sc := scanner.MustNew(scannerCfg)
	t.Cleanup(sc.Close)
	cfg := enabledA2ACfg()
	cfg.Action = config.ActionWarn
	body := []byte(`{"url":"https://blocked.vendor.example/message"}`)
	result := ScanA2AResponseBody(t.Context(), body, sc, cfg)
	if result.Clean || result.Action != config.ActionWarn || len(result.URLFindings) != 1 || len(result.InjectFindings) != 0 || len(result.DLPFindings) != 0 {
		t.Fatalf("protocol finding must retain its configured action: %+v", result)
	}
	w := httptest.NewRecorder()
	err := ScanA2AStream(t.Context(), strings.NewReader("data: "+string(body)+"\n\n"), w, w, sc, cfg)
	if !errors.Is(err, ErrA2AStreamFinding) || w.Body.Len() != 0 {
		t.Fatalf("native stream finding must terminate before forwarding: err=%v body=%s", err, w.Body.String())
	}
}
