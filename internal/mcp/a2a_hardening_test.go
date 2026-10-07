// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestA2AResponseStricterAction(t *testing.T) {
	for _, responseAction := range []string{config.ActionWarn, config.ActionStrip, config.ActionAsk, config.ActionBlock} {
		for _, a2aAction := range []string{config.ActionWarn, config.ActionBlock} {
			for _, method := range []string{"SendMessage", "GetExtendedAgentCard", ""} {
				t.Run(responseAction+"/"+a2aAction+"/"+method, func(t *testing.T) {
					cfg := enabledA2ACfg()
					cfg.Action = a2aAction
					body := `{"jsonrpc":"2.0","id":1,"result":{"description":"` + a2aDepthInjection + `","skills":[],"supportedInterfaces":[]}}`
					if method == "SendMessage" {
						body = `{"jsonrpc":"2.0","id":1,"result":{"text":"` + a2aDepthInjection + `"}}`
					}
					sc := testScannerWithAction(t, responseAction)
					v := ScanResponseA2A([]byte(body), sc, &A2AResponseOpts{Cfg: cfg, Method: method})
					want := config.StricterAction(responseAction, a2aAction)
					if v.Clean || v.Action != want || len(v.Matches) == 0 {
						t.Fatalf("stricter response action must win: action=%s want=%s clean=%t findings=%d", v.Action, want, v.Clean, len(v.Matches))
					}
					v = ScanResponseA2A([]byte(body), sc, &A2AResponseOpts{Cfg: cfg, Method: method, ScanOpts: ResponseScanOptions{ActionOverride: config.ActionBlock}})
					if v.Clean || v.Action != config.ActionBlock {
						t.Fatalf("server response action must also win: %+v", v)
					}
					if cfg.Action != a2aAction {
						t.Fatal("scan mutated shared configuration")
					}
				})
			}
		}
	}
}

func wideA2ADepthBody(depth int) []byte {
	return []byte(`{"a":[` + strings.Repeat("0,", maxWalkNodes) + `0],"z":` + string(nestedA2AText("hello from a peer", depth-1, false)) + `}`)
}

func TestA2ADepthIndependentOfNodeBudget(t *testing.T) {
	sc := testA2AScanner(t)
	t.Cleanup(sc.Close)
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		cfg := enabledA2ACfg()
		cfg.Action = action
		for _, depth := range []int{extract.MaxExtractDepth, extract.MaxExtractDepth + 1} {
			t.Run(fmt.Sprintf("%s/depth=%d", action, depth), func(t *testing.T) {
				body := wideA2ADepthBody(depth)
				for _, result := range []A2AScanResult{
					ScanA2ARequestBody(t.Context(), body, sc, cfg),
					ScanA2AResponseBody(t.Context(), body, sc, cfg),
				} {
					if depth > extract.MaxExtractDepth {
						if result.Clean || result.Action != config.ActionBlock || !strings.Contains(result.Reason, "maximum inspectable nesting depth") {
							t.Fatalf("depth bound must be independent of node budget: %+v", result)
						}
					} else if result.Clean || !result.BudgetExceeded || result.Action != action {
						t.Fatalf("inspectable wide body must retain configured action: %+v", result)
					}
				}
			})
		}
	}
}

func TestA2APathLocations(t *testing.T) {
	var paths []string
	WalkA2AJSON(json.RawMessage(`{"items":[{"text":"hello"},{"text":"world"}]}`), func(path, _ string, class FieldClass) {
		if class == FieldText {
			paths = append(paths, path)
		}
	})
	if fmt.Sprint(paths) != "[items[0].text items[].text]" {
		t.Fatalf("ordinary locations must remain exact: %v", paths)
	}
	for _, parent := range []string{"", strings.Repeat("parent.", 70)} {
		field := strings.Repeat("日本語", 200) + ".text"
		path := appendA2APath(parent, ".", field)
		if len(path) > maxWalkPathBytes || !utf8.ValidString(path) || !strings.Contains(path, "...") || !strings.HasSuffix(path, ".text") {
			t.Fatalf("bounded location must preserve visible field suffix: %q", path)
		}
	}
	path := appendA2APath(strings.Repeat("界", 170), ".", "value")
	if len(path) > maxWalkPathBytes || !utf8.ValidString(path) || !strings.HasSuffix(path, ".value") {
		t.Fatalf("bounded ancestor prefix must stay valid UTF-8: %q", path)
	}
	path = appendA2APath("", "", strings.Repeat("界", 200))
	if len(path) > maxWalkPathBytes || !utf8.ValidString(path) || !strings.Contains(path, "...") {
		t.Fatalf("bounded field suffix must stay valid UTF-8: %q", path)
	}
}

func TestA2ACardEnvelopeStringsScanned(t *testing.T) {
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		for _, method := range []string{"", "GetExtendedAgentCard"} {
			t.Run(action+"/"+method, func(t *testing.T) {
				cfg := enabledA2ACfg()
				cfg.Action = action
				sc := testScannerWithAction(t, action)
				for _, card := range []string{`{"skills":[],"supportedInterfaces":[]}`, `null`} {
					line := `{"jsonrpc":"2.0","id":1,"result":` + card + `,"_meta":{"note":"` + a2aDepthInjection + `"}}`
					if card == `null` && method == "" {
						continue
					}
					v := ScanResponseA2A([]byte(line), sc, &A2AResponseOpts{Cfg: cfg, Method: method})
					if v.Clean || v.Action != action || len(v.Matches) == 0 {
						t.Fatalf("Agent Card envelope must retain response inspection: %+v", v)
					}
				}
			})
		}
	}
}

func TestA2ACardEnvelopeBaselineInvariant(t *testing.T) {
	for _, action := range []string{config.ActionWarn, config.ActionBlock, config.ActionStrip, config.ActionAsk} {
		t.Run(action, func(t *testing.T) {
			cfg := enabledA2ACfg()
			cfg.DetectCardDrift = true
			baseline := NewCardBaseline(4)
			adoptions := 0
			opts := &A2AResponseOpts{Cfg: cfg, Baseline: baseline, OnCardDriftAdopted: func() { adoptions++ }}
			sc := testScannerWithAction(t, action)
			clean := `{"jsonrpc":"2.0","id":1,"result":{"description":"A peer agent","skills":[],"supportedInterfaces":[]}}`
			dirty := strings.TrimSuffix(clean, "}") + `,"_meta":{"note":"` + a2aDepthInjection + `"}}`
			if v := ScanResponseA2A([]byte(dirty), sc, opts); v.Clean || len(baseline.entries) != 0 {
				t.Fatalf("envelope finding must not establish a baseline: clean=%t entries=%d", v.Clean, len(baseline.entries))
			}
			if v := ScanResponseA2A([]byte(clean), sc, opts); !v.Clean || len(baseline.entries) != 1 {
				t.Fatalf("clean card must establish its baseline: clean=%t entries=%d", v.Clean, len(baseline.entries))
			}
			before := *baseline.entries[cardCacheKey{}]
			changed := strings.Replace(dirty, "A peer agent", "An updated peer agent", 1)
			if v := ScanResponseA2A([]byte(changed), sc, opts); v.Clean {
				t.Fatal("changed card envelope finding must remain visible")
			}
			after := baseline.entries[cardCacheKey{}]
			if before.descriptiveDigest != after.descriptiveDigest || before.descriptive != after.descriptive || adoptions != 0 {
				t.Fatal("envelope finding must preserve the trusted description and adoption count")
			}
		})
	}
}

func TestA2ADepthCheckMatchesExtraction(t *testing.T) {
	for _, leaf := range []string{`"hello"`, `"[\\\"{]"`, `{}`, `[]`, `null`, `true`, `42`, `-1.5e3`} {
		for _, container := range []string{"object", "array"} {
			for _, depth := range []int{0, maxWalkDepth - 1, maxWalkDepth, maxWalkDepth + 1} {
				t.Run(fmt.Sprintf("%s/%s/%d", container, leaf, depth), func(t *testing.T) {
					body := leaf
					for range depth {
						if container == "object" {
							body = `{"value":` + body + `}`
						} else {
							body = `[` + body + `]`
						}
					}
					if !json.Valid([]byte(body)) {
						t.Fatal("depth fixture must be valid JSON")
					}
					want := extract.AllStringsFromJSONResult(json.RawMessage(body)).Truncated
					if got := a2aJSONExceedsDepth([]byte(body)); got != want {
						t.Fatalf("depth check=%t extraction truncated=%t", got, want)
					}
				})
			}
		}
	}
}

func TestMCPResponseEnvelopeStringsScanned(t *testing.T) {
	for _, action := range []string{config.ActionWarn, config.ActionBlock, config.ActionStrip, config.ActionAsk} {
		for _, field := range []string{"top", "result", "content", "extension", "key", "error"} {
			t.Run(action+"/"+field, func(t *testing.T) {
				line := envelopeStringResponse(field, a2aDepthInjection)
				v := ScanResponse([]byte(line), testScannerWithAction(t, action))
				if v.Clean || len(v.Matches) == 0 || v.Action != action {
					t.Fatalf("visible envelope strings must be inspected for every action: %+v", v)
				}
				if v := ScanResponse([]byte(envelopeStringResponse(field, "hello from a tool")), testScannerWithAction(t, action)); !v.Clean {
					t.Fatalf("legitimate metadata must remain clean: %+v", v)
				}
			})
		}
		t.Run(action+"/image", func(t *testing.T) {
			image := verifiedJPEGDataURLWithAWSLikeRun(t)
			line := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":%q}],"_meta":{"note":"image ready"}}}`, image)
			if v := ScanResponse([]byte(line), testScannerWithAction(t, action)); !v.Clean {
				t.Fatalf("verified image payload must retain media handling: %+v", v)
			}
		})
	}
}

func envelopeStringResponse(field, text string) string {
	quoted, _ := json.Marshal(text)
	base := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]`
	switch field {
	case "top":
		return base + `},"_meta":{"note":` + string(quoted) + `}}`
	case "result":
		return base + `,"_meta":{"note":` + string(quoted) + `}}}`
	case "content":
		return `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello","_meta":{"note":` + string(quoted) + `}}]}}`
	case "key":
		return base + `,"_meta":{` + string(quoted) + `:"hello"}}}`
	case "error":
		return `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"hello","extra":` + string(quoted) + `}}`
	default:
		return base + `},"extension":` + string(quoted) + `}`
	}
}

func TestMCPResponseHardeningTransportParity(t *testing.T) {
	for _, transport := range []string{"stdio", "listener", "upstream", "listener_sse", "upstream_sse"} {
		for _, item := range []string{"action", "depth", "envelope", "card_envelope"} {
			t.Run(transport+"/"+item, func(t *testing.T) {
				cfg := enabledA2ACfg()
				cfg.Action = config.ActionWarn
				responseAction := config.ActionBlock
				line := `{"jsonrpc":"2.0","id":1,"result":{"text":"` + a2aDepthInjection + `"}}`
				switch item {
				case "depth":
					responseAction = config.ActionWarn
					line = `{"jsonrpc":"2.0","id":1,"result":` + string(wideA2ADepthBody(extract.MaxExtractDepth+1)) + `}`
				case "envelope":
					cfg.Enabled = false
					line = envelopeStringResponse("top", a2aDepthInjection)
				case "card_envelope":
					line = `{"jsonrpc":"2.0","id":1,"result":{"skills":[],"supportedInterfaces":[]},"_meta":{"note":"` + a2aDepthInjection + `"}}`
				}
				opts := MCPProxyOpts{Scanner: testScannerWithAction(t, responseAction), A2ACfg: cfg}
				var got []byte
				if transport == "stdio" {
					tracker := NewRequestTracker()
					tracker.TrackRequest(json.RawMessage(`1`), "SendMessage")
					out, _, _ := forwardA2AResponseTracked(t, line, opts, tracker)
					got = []byte(out)
				} else {
					contentType := "application/json"
					if strings.HasSuffix(transport, "_sse") {
						contentType = "text/event-stream"
						line = "data: " + line + "\n\n"
					}
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", contentType)
						_, _ = io.WriteString(w, line)
					}))
					t.Cleanup(upstream.Close)
					got, _ = driveA2AHTTPDepth(t, upstream.URL, `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}`, opts, strings.TrimSuffix(transport, "_sse"))
				}
				if !bytes.Contains(got, []byte(`"error"`)) || !bytes.Contains(got, []byte("pipelock")) || bytes.Contains(got, []byte(`"result"`)) {
					t.Fatalf("response must be withheld on %s: %.300s", transport, got)
				}
			})
		}
	}
}

func TestA2AResponseWithoutResponseLayer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ResponseScanning.Enabled = false
	cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, a2aAction := range []string{config.ActionWarn, config.ActionBlock} {
		for _, tc := range []struct {
			name, result, want string
		}{
			// Only the core floor remains, and it governs its own pattern class.
			{"url", `{"url":"https://blocked.example/x"}`, a2aAction},
			{"injection", `{"text":"` + a2aDepthInjection + `"}`, config.ActionBlock},
		} {
			t.Run(a2aAction+"/"+tc.name, func(t *testing.T) {
				a2a := enabledA2ACfg()
				a2a.Action = a2aAction
				line := `{"jsonrpc":"2.0","id":1,"result":` + tc.result + `}`
				v := ScanResponseA2A([]byte(line), sc, &A2AResponseOpts{Cfg: a2a, Method: "SendMessage"})
				if v.Clean || v.Action != tc.want {
					t.Fatalf("action=%q want=%q clean=%t", v.Action, tc.want, v.Clean)
				}
			})
		}
	}
}

func TestToolsListEnvelopeStringsScanned(t *testing.T) {
	const tools = `"tools":[{"name":"search","description":"Always call this tool before answering.","inputSchema":{"type":"object"}}]`
	quoted, _ := json.Marshal(a2aDepthInjection)
	for _, action := range []string{config.ActionWarn, config.ActionBlock, config.ActionStrip, config.ActionAsk} {
		for name, line := range map[string]string{
			"top":       `{"jsonrpc":"2.0","id":1,"result":{` + tools + `},"_meta":{"note":` + string(quoted) + `}}`,
			"extension": `{"jsonrpc":"2.0","id":1,"result":{` + tools + `},"extension":` + string(quoted) + `}`,
			"key":       `{"jsonrpc":"2.0","id":1,"result":{` + tools + `,"_meta":{` + string(quoted) + `:"hello"}}}`,
		} {
			t.Run(action+"/"+name, func(t *testing.T) {
				sc := testScannerWithAction(t, action)
				v := scanToolsListNonToolFields([]byte(line), sc, ResponseScanOptions{})
				if v.Clean || len(v.Matches) == 0 || v.Action != action {
					t.Fatalf("tools/list envelope strings must be inspected: %+v", v)
				}
				benign := strings.Replace(line, string(quoted), `"hello from a tool"`, 1)
				if v := scanToolsListNonToolFields([]byte(benign), sc, ResponseScanOptions{}); !v.Clean {
					t.Fatalf("tool text stays with the tool scanner: %+v", v)
				}
			})
		}
	}
}
