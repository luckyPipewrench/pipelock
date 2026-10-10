// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// The required-receipt matrix builds a full proxy and scanner for every
// combination, which made one test run for about ten minutes under the race
// detector and overloaded a single CI shard. Each surface is its own top-level
// test so the shard planner can spread them, and the combinations within a
// surface run in parallel; every combination is still exercised.
func TestRequiredResponsePolicyReceiptsFetch(t *testing.T) {
	runRequiredResponsePolicyReceipts(t, "fetch")
}

func TestRequiredResponsePolicyReceiptsForward(t *testing.T) {
	runRequiredResponsePolicyReceipts(t, "forward")
}

func TestRequiredResponsePolicyReceiptsIntercept(t *testing.T) {
	runRequiredResponsePolicyReceipts(t, "intercept")
}

func TestRequiredResponsePolicyReceiptsReverse(t *testing.T) {
	runRequiredResponsePolicyReceipts(t, "reverse")
}

// runRequiredResponsePolicyReceipts runs every shape, grouping and failure mode
// for one surface. The parent stays sequential with other top-level tests
// because installArtifactOfficialKey swaps package keyring globals; its
// parallel subtests only read them, and the parent's cleanup restores them
// after every subtest has finished.
func runRequiredResponsePolicyReceipts(t *testing.T, surface string) {
	artifactKey := installArtifactOfficialKey(t)
	{
		for _, shape := range []string{"media", "media relabel", "shield", "shield head", "shield warn", "a2a", "card first", "card adopt", "card signature", "scan warn", "scan strip", "scan hidden", "sse warn", "approve", "approve strip", "artifact", "passthrough"} {
			if (shape == "artifact" && surface != "forward" && surface != "intercept") || (shape == "passthrough" && surface == "fetch") {
				continue
			}
			if (shape == "a2a" || strings.HasPrefix(shape, "card")) && surface != "forward" && surface != "intercept" {
				continue
			}
			if strings.HasPrefix(shape, "approve") && surface != "fetch" {
				continue
			}
			if shape == "sse warn" && surface == "fetch" {
				continue
			}

			for _, grouped := range []bool{false, true} {
				for _, failure := range []string{"healthy", "missing", "v1", "v2", "v1 sync", "v2 sync", "optional"} {
					t.Run(surface+"/"+shape+"/"+map[bool]string{false: "single", true: "group"}[grouped]+"/"+failure, func(t *testing.T) {
						t.Parallel()
						// A grouped run replaces the recorder and source with the
						// failure group, so the dual-emit fixture (a whole proxy and
						// scanner) is built only for the single-recorder runs that
						// use it.
						var f *dualEmitFixture
						var source *Proxy
						var rec *recorder.Recorder
						if grouped {
							rec, _, source, _ = newReceiptFailureGroup(t)
							_ = source.admitReceiptShard()
						} else {
							f = newDualEmitFixture(t, false)
							source, rec = f.p, f.rec
						}
						cfg := config.Defaults()
						cfg.Internal = nil
						cfg.Taint.Enabled = false
						if shape == "media relabel" {
							disabled := false
							cfg.MediaPolicy.StripImageMetadata = &disabled
						}
						cfg.FlightRecorder.RequireReceipts = failure != "optional"
						cfg.ForwardProxy.Enabled = true
						cfg.ResponseScanning.Enabled = strings.HasPrefix(shape, "scan") || strings.HasPrefix(shape, "approve") || shape == "sse warn"
						if shape == "artifact" {
							cfg.ResponseScanning.AuthenticatedArtifacts = []config.AuthenticatedArtifactEntry{{Host: "api.vendor.example", Path: "/content", BundleName: "pipelock-community"}}
						}
						if shape == "passthrough" {
							cfg.TLSInterception.MaxResponseBytes = 128
							cfg.ResponseScanning.Enabled = true
							cfg.ResponseScanning.SizeExemptDomains = []string{"api.vendor.example"}
							cfg.ResponseScanning.UnscannablePassthrough = []config.UnscannablePassthroughEntry{{Host: "api.vendor.example", Paths: []string{"/content"}, ContentTypes: []string{"application/octet-stream"}, Reason: "opaque artifact", Expires: time.Now().AddDate(1, 0, 0).Format(time.DateOnly)}}
						}
						cfg.ResponseScanning.Action = config.ActionWarn
						cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: "POLICY_MARKER"}}
						if shape == "scan strip" {
							cfg.ResponseScanning.Action = config.ActionStrip
						}
						if strings.HasPrefix(shape, "approve") {
							cfg.ResponseScanning.Action = config.ActionAsk
						}
						cfg.ResponseScanning.SSEStreaming.Enabled = true
						cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
						cfg.BrowserShield.Enabled = strings.HasPrefix(shape, "shield")
						if shape == "shield head" || shape == "shield warn" {
							cfg.BrowserShield.MaxShieldBytes = 256
							cfg.BrowserShield.OversizeAction = config.ShieldOversizeScanHead
							if shape == "shield warn" {
								cfg.BrowserShield.OversizeAction = config.ShieldOversizeWarn
							}
						}
						cfg.A2AScanning.Enabled = shape == "a2a" || strings.HasPrefix(shape, "card")
						cfg.A2AScanning.Action = config.ActionWarn
						cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
						var signedCard []byte
						if shape == "card signature" {
							pub, priv, keyErr := ed25519.GenerateKey(nil)
							if keyErr != nil {
								t.Fatal(keyErr)
							}
							cfg.A2AScanning.DetectCardDrift = false
							cfg.A2AScanning.TrustedAgentCardKeys = []config.A2ATrustedCardKey{{KeyID: "k1", PublicKey: signing.EncodePublicKey(pub), AllowedOrigins: []string{"https://api.vendor.example"}}}
							signedCard = e2eSignedCard(t, priv, false)
						}
						sc := scanner.MustNew(cfg)
						p, err := New(cfg, source.logger, sc, source.metrics, WithRecorder(rec), WithReceiptEmitter(source.receiptEmitterPtr.Load()), WithV2ReceiptEmitter(source.v2EmitterPtr.Load()))
						if err != nil {
							t.Fatal(err)
						}
						defer p.Close()
						if shape == "passthrough" {
							p.responseBodyLimit = 128
						}
						p.receiptGroupPtr.Store(source.receiptGroupPtr.Load())
						if strings.HasPrefix(shape, "approve") {
							answer := "y\n"
							if shape == "approve strip" {
								answer = "s\n"
							}
							p.approver = hitl.New(5, hitl.WithInput(strings.NewReader(answer)), hitl.WithOutput(&bytes.Buffer{}), hitl.WithTerminal(true))
							defer p.approver.Close()
						}

						var syncs atomic.Int32
						target := "https://api.vendor.example/content"
						if strings.HasPrefix(shape, "card") {
							target = "https://api.vendor.example" + agentCardPath
							if surface == "intercept" {
								target = "https://api.vendor.example:443" + agentCardPath
							}
						}
						ctype, payload, marker := "image/png", string(buildValidPNG([]byte("Description\x00metadata-marker"))), "pixel bytes"
						if shape == "media relabel" {
							ctype = "image/jpeg"
						}
						if strings.HasPrefix(shape, "shield") {
							ctype, payload, marker = "text/html", `<html><head></head><body><a href="chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/page.html">extension</a><p>ordinary text</p></body></html>`, "ordinary text"
						}
						if shape == "shield head" || shape == "shield warn" {
							payload += strings.Repeat(" ", 1024)
						}
						if shape == "a2a" {
							ctype, payload, marker = "application/a2a+json", `{"url":"https://blocked.example/content","text":"ordinary text"}`, "ordinary text"
							result := mcp.ScanA2AResponseBody(t.Context(), []byte(payload), sc, &cfg.A2AScanning)
							if result.Clean || result.ScanError != "" {
								t.Fatalf("invalid finding control: %+v", result)
							}
						}
						if strings.HasPrefix(shape, "scan") || strings.HasPrefix(shape, "approve") {
							ctype, payload, marker = "text/plain", "ordinary text POLICY_MARKER rest", "ordinary text"
						}
						if shape == "scan hidden" {
							ctype, payload, marker = "text/html", "<html><body><p>ordinary text</p><!-- POLICY_MARKER --></body></html>", "ordinary text"
						}
						if shape == "sse warn" {
							ctype, payload, marker = "text/event-stream", "data: {\"text\":\"ordinary text POLICY_MARKER rest\"}\n\n", "ordinary text"
						}

						originalCard := []byte(`{"name":"Document helper","description":"ordinary text","skills":[{"id":"read","name":"Read documents","description":"Read documents"}]}`)
						if strings.HasPrefix(shape, "card") {
							ctype, payload, marker = "application/json", string(originalCard), "ordinary text"
							if shape == "card adopt" {
								initial := mcp.ScanAgentCard(t.Context(), originalCard, sc, p.a2aCardBaseline, mcp.CardCacheKeyFromRequest(target, ""), &cfg.A2AScanning)
								if !initial.Clean || !initial.FirstSeen {
									t.Fatalf("invalid initial card: %+v", initial)
								}
								payload = strings.Replace(payload, "ordinary text", "ordinary text with details", 1)
							}
							if shape == "card signature" {
								payload, marker = string(signedCard), "Vendor Agent"
								control := mcp.ScanAgentCard(t.Context(), signedCard, sc, nil, mcp.CardCacheKeyFromRequest(target, ""), &cfg.A2AScanning)
								if !control.Clean || !control.SignatureVerified {
									t.Fatalf("invalid signed card: %+v", control)
								}
							}
						}

						if shape == "artifact" {
							ctype, payload, marker = "text/plain", string(artifactBundle("ordinary text POLICY_MARKER")), "ordinary text"
						}
						if shape == "passthrough" {
							ctype, payload, marker = "application/octet-stream", strings.Repeat("Z", 1024), strings.Repeat("Z", 32)
						}
						admitted := false
						rt := forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
							if shape == "artifact" && strings.HasSuffix(req.URL.Path, ".sig") {
								return artifactResponse(req, http.StatusOK, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(artifactKey, []byte(payload))))), nil
							}
							admitted = true
							rec.SetSyncForTest(func(*os.File) error {
								n := syncs.Add(1)
								if failure == "v1 sync" && n == 1 || failure == "v2 sync" && n == 2 {
									return errors.New("response sync failure")
								}
								return nil
							})
							e1, e2 := p.receiptEmitterPtr.Load(), p.v2EmitterPtr.Load()
							if group := p.receiptGroupPtr.Load(); group != nil {
								// Every transport selected the second admission shard. The process
								// fallback is deliberately healthy to expose a lost selection.
								selected := receipt.EmitOpts{ShardSelected: true, ShardIndex: 1}
								e1, err = group.shards.SelectedEmitter(selected)
								if err != nil {
									t.Fatal(err)
								}
								e2 = group.v2[selected.ShardIndex]
							}
							switch failure {
							case "missing":
								p.receiptGroupPtr.Store(nil)
								p.receiptEmitterPtr.Store(nil)
								p.v2EmitterPtr.Store(nil)
							case "v1":
								e1.MarkUnhealthy(errors.New("response writer failure"))
							case "v2", "optional":
								if _, _, retireErr := e2.Retire(); retireErr != nil {
									t.Fatal(retireErr)
								}
							}
							header := http.Header{"Content-Type": {ctype}}
							if shape == "passthrough" {
								header.Set("Content-Disposition", `attachment; filename="artifact.bin"`)
								header.Set("Content-Length", strconv.Itoa(len(payload)))
							}
							return &http.Response{StatusCode: http.StatusOK, Header: header, ContentLength: int64(len(payload)), Body: io.NopCloser(strings.NewReader(payload)), Request: req}, nil
						})
						p.client = &http.Client{Transport: rt}
						requestURL := target
						if surface == "fetch" {
							requestURL = "/fetch?url=" + target
						}
						req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, requestURL, nil)
						if shape == "a2a" {
							req.Header.Set("Content-Type", ctype)
						}
						w := &receiptDeliveryWriter{ResponseRecorder: httptest.NewRecorder(), syncs: &syncs}
						var tracker *reverseOutcomeTracker
						switch surface {
						case "fetch":
							p.handleFetch(w, req)
						case "forward":
							p.handleForwardHTTP(w, req)
						case "intercept":
							newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt).ServeHTTP(w, req)
						case "reverse":
							selected := p.admitReceiptShard()
							reverseActionID := receipt.NewActionID()
							req = req.WithContext(context.WithValue(req.Context(), ctxKeyReverseActionID, reverseActionID))
							tracker = newReverseOutcomeTracker(cfg, receipt.EmitOpts{})
							req = req.WithContext(context.WithValue(context.WithValue(req.Context(), ctxKeyReceiptShard, selected), ctxKeyReverseOutcome, tracker))
							if err := p.emitRequiredReceipt(withReceiptShard(receipt.EmitOpts{ActionID: reverseActionID, Verdict: config.ActionAllow, Transport: TransportReverse, Method: http.MethodGet, Target: target}, selected)); err != nil {
								t.Fatal(err)
							}
							resp, rtErr := rt.RoundTrip(req)
							if rtErr != nil {
								t.Fatal(rtErr)
							}
							rp := &ReverseProxyHandler{cfgPtr: &p.cfgPtr, scPtr: &p.scannerPtr, logger: p.logger, metrics: p.metrics, owner: p, shieldEngine: p.shieldEngine, captureObs: p.captureObs, receiptEmitterPtr: &p.receiptEmitterPtr, v2EmitterPtr: &p.v2EmitterPtr, envelopeEmitterPtr: &p.envelopeEmitterPtr, envelopeVerifierPtr: &p.envelopeVerifierPtr}
							if shape == "passthrough" {
								rp.responseBodyLimit = 128
							}
							if err := rp.modifyResponse(resp); err != nil {
								t.Fatal(err)
							}
							b, readErr := io.ReadAll(resp.Body)
							_ = resp.Body.Close()
							if shape == "sse warn" && failure != "healthy" && failure != "optional" && !errors.Is(readErr, mcp.ErrReceiptRequired) {
								t.Fatalf("receipt failure ended stream without error: %v", readErr)
							}
							if readErr != nil && (shape != "sse warn" || !errors.Is(readErr, mcp.ErrReceiptRequired)) {
								t.Fatal(readErr)
							}
							for key, values := range resp.Header {
								w.Header()[key] = values
							}
							w.WriteHeader(resp.StatusCode)
							_, _ = w.Write(b)
						}
						if !admitted {
							t.Fatal("request never reached admitted upstream")
						}
						want := failure == "healthy" || failure == "optional"
						delivered := strings.Contains(w.Body.String(), marker)
						if delivered != want {
							t.Fatalf("delivered=%t want=%t status=%d body=%q", delivered, want, w.Code, w.Body.String())
						}
						if !want {
							if shape != "sse warn" && (w.Code != http.StatusForbidden || w.Header().Get("X-Pipelock-Block-Reason") != "receipt_emission_failed") {
								t.Fatalf("untruthful failure: status=%d headers=%v", w.Code, w.Header())
							}
							statsRecorder := httptest.NewRecorder()
							p.metrics.StatsHandler()(statsRecorder, req)
							var stats struct {
								Receipts struct {
									RequiredBlocks []struct {
										Reason, Transport string
										Count             int
									} `json:"required_blocks"`
								}
							}
							if err := json.Unmarshal(statsRecorder.Body.Bytes(), &stats); err != nil {
								t.Fatal(err)
							}
							if len(stats.Receipts.RequiredBlocks) == 0 {
								t.Fatalf("receipt block absent from operator stats: %s", statsRecorder.Body.String())
							}

							if tracker != nil {
								tracker.mu.Lock()
								reason := tracker.reason
								tracker.mu.Unlock()
								if reason != receiptEmissionFailedLayer {
									t.Fatalf("outcome=%q", reason)
								}
							}
						}
						if want && shape == "media relabel" {
							if surface == "fetch" {
								if !strings.Contains(w.Body.String(), `"content_type":"image/png"`) {
									t.Fatalf("relabel missing: %s", w.Body.String())
								}
							} else if w.Header().Get("Content-Type") != "image/png" {
								t.Fatalf("relabel missing: %v", w.Header())
							}
						}
						if want && shape == "media" && bytes.Contains(w.Body.Bytes(), []byte("metadata-marker")) {
							t.Fatal("metadata not stripped")
						}
						if want && (shape == "shield" || shape == "shield head") && strings.Contains(w.Body.String(), "chrome-extension") {
							t.Fatal("shield did not rewrite")
						}
						if shape == "card first" || shape == "card adopt" {
							check := originalCard
							if want {
								check = []byte(payload)
							}
							state := mcp.ScanAgentCard(t.Context(), check, sc, p.a2aCardBaseline, mcp.CardCacheKeyFromRequest(target, ""), &cfg.A2AScanning)
							if shape == "card first" && !want {
								if !state.FirstSeen {
									t.Fatal("failed confirmation seeded baseline")
								}
							} else if !state.Clean || state.DriftDetected {
								t.Fatalf("baseline changed before confirmation: %+v", state)
							}
						}
						if want && (shape == "scan strip" || shape == "approve strip") && strings.Contains(w.Body.String(), "POLICY_MARKER") {
							t.Fatal("strip kept finding")
						}

						if !grouped && failure == "healthy" {
							if err := rec.Close(); err != nil {
								t.Fatal(err)
							}
							records := extractReceiptsFromDir(t, f.dir)
							var requestID string
							for _, rcpt := range records {
								if rcpt.ActionRecord.DecisionPhase == receipt.DecisionPhaseIntent {
									requestID = rcpt.ActionRecord.ActionID
									break
								}
							}
							if requestID == "" {
								t.Fatal("missing request receipt positive control")
							}
							for _, rcpt := range records {
								r := rcpt.ActionRecord
								if r.DecisionPhase != "" || r.Verdict == config.ActionBlock {
									continue
								}
								if r.ActionID == requestID || r.ParentActionID != requestID {
									t.Errorf("response decision is not a child of request: %+v", r)
								}
							}
						}
						if !grouped && surface == "fetch" && !want && failure == "v2" && strings.HasPrefix(shape, "scan") {
							if err := rec.Close(); err != nil {
								t.Fatal(err)
							}
							records := extractReceiptsFromDir(t, f.dir)
							found := false
							for _, rcpt := range records {
								r := rcpt.ActionRecord
								if r.DecisionPhase == receipt.DecisionPhaseOutcome {
									found = true
									if !strings.Contains(r.Pattern, "reason="+receiptEmissionFailedLayer) || !strings.Contains(r.Pattern, "status=403") {
										t.Errorf("receipt failure misclassified: %s", r.Pattern)
									}
								}
							}
							if !found {
								t.Fatal("missing fetch outcome")
							}
						}
						if failure == "healthy" && w.syncsAtDelivery < 2 {
							t.Fatalf("both families not synced before delivery: %d", w.syncsAtDelivery)
						}
						if failure == "optional" && syncs.Load() != 0 {
							t.Fatalf("optional forced sync: %d", syncs.Load())
						}
					})
				}
			}
		}
	}
}

// receiptDeliveryWriter observes the first client write, independently of any
// later outcome receipt. Recording after delivery cannot satisfy this check.
type receiptDeliveryWriter struct {
	*httptest.ResponseRecorder
	syncs           *atomic.Int32
	syncsAtDelivery int32
}

func (w *receiptDeliveryWriter) Write(body []byte) (int, error) {
	if w.Body.Len() == 0 {
		w.syncsAtDelivery = w.syncs.Load()
	}
	return w.ResponseRecorder.Write(body)
}

// A checked-in image exercises a producer independent of the chunk fixture.
func TestRequiredMediaRealImage(t *testing.T) {
	original, err := os.ReadFile("../../assets/icons/pipelock-logo-64.png")
	if err != nil {
		t.Fatal(err)
	}
	before, err := png.Decode(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	metadata := proxyTestPNGChunk("tEXt", []byte("Description\x00metadata-marker"))
	payload := append(append(append([]byte(nil), original[:33]...), metadata...), original[33:]...)
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "v2 outage"}[failure], func(t *testing.T) {
			f := newDualEmitFixture(t, false)
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.FlightRecorder.RequireReceipts = true
			cfg.ForwardProxy.Enabled = true
			cfg.ResponseScanning.Enabled = false
			sc := scanner.MustNew(cfg)
			p, err := New(cfg, f.p.logger, sc, f.p.metrics, WithRecorder(f.rec), WithReceiptEmitter(f.p.receiptEmitterPtr.Load()), WithV2ReceiptEmitter(f.p.v2EmitterPtr.Load()))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			var syncs atomic.Int32
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
				f.rec.SetSyncForTest(func(*os.File) error { syncs.Add(1); return nil })
				if failure {
					if _, _, err := p.v2EmitterPtr.Load().Retire(); err != nil {
						t.Fatal(err)
					}
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"image/png"}}, Body: io.NopCloser(bytes.NewReader(payload)), Request: req}, nil
			})}
			w := &receiptDeliveryWriter{ResponseRecorder: httptest.NewRecorder(), syncs: &syncs}
			p.handleForwardHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/image", nil))
			if failure {
				if w.Code != http.StatusForbidden || w.Header().Get("X-Pipelock-Block-Reason") != "receipt_emission_failed" {
					t.Fatalf("failure delivered: %d", w.Code)
				}
				return
			}
			if w.syncsAtDelivery < 2 || bytes.Contains(w.Body.Bytes(), []byte("metadata-marker")) {
				t.Fatalf("unconfirmed or unstripped image: syncs=%d", w.syncsAtDelivery)
			}
			after, err := png.Decode(bytes.NewReader(w.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			if before.Bounds() != after.Bounds() {
				t.Fatal("image dimensions changed")
			}
			for y := before.Bounds().Min.Y; y < before.Bounds().Max.Y; y++ {
				for x := before.Bounds().Min.X; x < before.Bounds().Max.X; x++ {
					br, bg, bb, ba := before.At(x, y).RGBA()
					ar, ag, ab, aa := after.At(x, y).RGBA()
					if br != ar || bg != ag || bb != ab || ba != aa {
						t.Fatal("image pixels changed")
					}
				}
			}
		})
	}
}

func TestRequiredDeniedSignedCardKeepsPolicyReason(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	card := map[string]any{"name": "Vendor Agent", "description": "ordinary text", "url": "https://blocked.example/content"}
	preimage := e2ePreimage(t, card)
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1"}`))
	sig := ed25519.Sign(priv, []byte(protected+"."+base64.RawURLEncoding.EncodeToString(preimage)))
	card["signatures"] = []any{map[string]any{"protected": protected, "signature": base64.RawURLEncoding.EncodeToString(sig)}}
	body, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range []string{"forward", "intercept"} {
		for _, outage := range []bool{false, true} {
			t.Run(surface+"/"+map[bool]string{false: "healthy", true: "v2 outage"}[outage], func(t *testing.T) {
				f := newDualEmitFixture(t, false)
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.Taint.Enabled = false
				cfg.ForwardProxy.Enabled = true
				cfg.ResponseScanning.Enabled = false
				cfg.FlightRecorder.RequireReceipts = true
				cfg.A2AScanning.Enabled = true
				cfg.A2AScanning.Action = config.ActionBlock
				cfg.A2AScanning.DetectCardDrift = false
				cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.example"}
				cfg.A2AScanning.TrustedAgentCardKeys = []config.A2ATrustedCardKey{{KeyID: "k1", PublicKey: signing.EncodePublicKey(pub), AllowedOrigins: []string{"https://api.vendor.example"}}}
				sc := scanner.MustNew(cfg)
				control := mcp.ScanAgentCard(t.Context(), body, sc, nil, mcp.CardCacheKeyFromRequest("https://api.vendor.example"+agentCardPath, ""), &cfg.A2AScanning)
				if control.Clean || !control.SignatureVerified || control.Action != config.ActionBlock {
					t.Fatalf("invalid denied signed card control: %+v", control)
				}
				p, err := New(cfg, f.p.logger, sc, f.p.metrics, WithRecorder(f.rec), WithReceiptEmitter(f.p.receiptEmitterPtr.Load()), WithV2ReceiptEmitter(f.p.v2EmitterPtr.Load()))
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				rt := forwardBoundaryRoundTripper(func(req *http.Request) (*http.Response, error) {
					if outage {
						if _, _, err := p.v2EmitterPtr.Load().Retire(); err != nil {
							t.Fatal(err)
						}
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/a2a+json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
				})
				p.client = &http.Client{Transport: rt}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example"+agentCardPath, nil)
				w := httptest.NewRecorder()
				if surface == "forward" {
					p.handleForwardHTTP(w, req)
				} else {
					newInterceptHandler(&InterceptContext{TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: p.logger, Metrics: p.metrics, Proxy: p}, rt).ServeHTTP(w, req)
				}
				if w.Code != http.StatusForbidden || w.Header().Get("X-Pipelock-Block-Reason") != "prompt_injection" {
					t.Fatalf("denied path lost policy reason: status=%d headers=%v body=%s", w.Code, w.Header(), w.Body.String())
				}
			})
		}
	}
}
