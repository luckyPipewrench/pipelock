// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// newTestEngine builds an Engine with a fresh lab key under a temp dir.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func TestDefaultScenarios_PublicContract(t *testing.T) {
	t.Parallel()

	want := []struct {
		id        string
		transport string
		verdict   string
		layer     string
	}{
		{"allowed-safe-read", TransportFetch, verdictAllow, ""},
		{"secret-exfil-url-blocked", TransportFetch, verdictBlock, "core_dlp"},
		{"prompt-injection-response-blocked", TransportFetch, verdictBlock, "response_scan"},
		{"ssrf-internal-target-blocked", TransportFetch, verdictBlock, "ssrf_metadata"},
		{"operation-aware-policy", TransportForward, verdictBlock, "request_policy"},
		{"poisoned-ticket-webhook-exfil", TransportForward, verdictBlock, "body_dlp"},
		{"poisoned-readme-key-paste", TransportForward, verdictBlock, "body_dlp"},
		{"hostile-page-session-keys", TransportForward, verdictBlock, "body_dlp"},
	}

	got := DefaultScenarios()
	if len(got) != len(want) {
		t.Fatalf("DefaultScenarios count = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		s := got[i]
		if s.ID != w.id {
			t.Errorf("scenario[%d].ID = %q, want %q", i, s.ID, w.id)
		}
		if s.Transport != w.transport {
			t.Errorf("%s transport = %q, want %q", s.ID, s.Transport, w.transport)
		}
		if s.ExpectedVerdict != w.verdict {
			t.Errorf("%s verdict = %q, want %q", s.ID, s.ExpectedVerdict, w.verdict)
		}
		if s.ExpectedLayer != w.layer {
			t.Errorf("%s layer = %q, want %q", s.ID, s.ExpectedLayer, w.layer)
		}
	}
}

// TestCapture_AllScenarios drives every default scenario through a real proxy
// and asserts the captured, signed receipt chain matches the declared expected
// verdict. This is the integration guard: if the real scanner pipeline disagrees
// with a scenario's claimed outcome, this fails.
func TestCapture_AllScenarios(t *testing.T) {
	t.Parallel()

	for _, s := range DefaultScenarios() {
		s := s
		t.Run(s.ID, func(t *testing.T) {
			t.Parallel()

			eng := newTestEngine(t)
			got, err := eng.Capture(s)
			if err != nil {
				t.Fatalf("Capture(%s): %v", s.ID, err)
			}

			if !got.ChainResult.Valid {
				t.Fatalf("captured chain invalid: %s", got.ChainResult.Error)
			}
			if got.ReceiptCount == 0 {
				t.Fatalf("no receipts captured")
			}

			// Every captured receipt must verify against the signer key.
			if res := receipt.VerifyChain(got.Receipts, got.SignerKeyHex); !res.Valid {
				t.Fatalf("re-verify failed: %s", res.Error)
			}

			decisive := decisiveReceipt(got.Receipts, s.ExpectedVerdict)
			if decisive == nil {
				t.Fatalf("no receipt with expected verdict %q; got verdicts %v",
					s.ExpectedVerdict, verdictsOf(got.Receipts))
			}

			// Policy hash on the receipt must equal the config hash we stamped.
			if decisive.ActionRecord.PolicyHash != got.PolicyHash {
				t.Errorf("policy hash mismatch: receipt=%q engine=%q",
					decisive.ActionRecord.PolicyHash, got.PolicyHash)
			}
			if s.ExpectedLayer != "" && decisive.ActionRecord.Layer != s.ExpectedLayer {
				t.Errorf("decisive layer=%q want %q", decisive.ActionRecord.Layer, s.ExpectedLayer)
			}

			t.Logf("scenario %s: %d receipt(s), decisive verdict=%s layer=%q pattern=%q target=%q",
				s.ID, got.ReceiptCount, decisive.ActionRecord.Verdict,
				decisive.ActionRecord.Layer, decisive.ActionRecord.Pattern, decisive.ActionRecord.Target)
		})
	}
}

func TestCapture_EarlyErrorAfterRecorderConstructionClosesRecorder(t *testing.T) {
	cases := map[string]struct {
		configure func(*Engine)
		wantErr   string
	}{
		"emitter construction": {
			configure: func(eng *Engine) {
				eng.privKey = nil
			},
			wantErr: "emitter construction failed",
		},
		"session open": {
			configure: func(_ *Engine) {
				afterRecorderConstructedForTest = func(rec *recorder.Recorder) {
					_ = rec.Close()
				}
			},
			wantErr: "session_open receipt",
		},
		"proxy construction": {
			configure: func(_ *Engine) {
				beforeProxyConstructedForTest = func(cfg *config.Config) {
					cfg.MediationEnvelope.Enabled = true
					cfg.MediationEnvelope.Sign = true
					cfg.MediationEnvelope.SigningKeyPath = filepath.Join(t.TempDir(), "missing-envelope.key")
				}
			},
			wantErr: "proxy:",
		},
		"drive": {
			configure: func(_ *Engine) {
				beforeDriveScenarioForTest = func(s *Scenario) {
					s.ID = "unknown-after-proxy"
				}
			},
			wantErr: "drive:",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			afterRecorderConstructedForTest = nil
			beforeProxyConstructedForTest = nil
			beforeDriveScenarioForTest = nil
			closed := make(chan struct{}, 1)
			afterEarlyRecorderCloseForTest = func() {
				closed <- struct{}{}
			}
			t.Cleanup(func() {
				afterEarlyRecorderCloseForTest = nil
				afterRecorderConstructedForTest = nil
				beforeProxyConstructedForTest = nil
				beforeDriveScenarioForTest = nil
			})

			eng := newTestEngine(t)
			tc.configure(eng)

			_, err := eng.Capture(DefaultScenarios()[0])
			if err == nil {
				t.Fatalf("Capture unexpectedly succeeded for %s", name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Capture error = %q, want %q", err, tc.wantErr)
			}

			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("recorder close hook was not invoked on early Capture error")
			}
		})
	}
}

func TestCapture_DecisivePatternsMatchPublishedClaims(t *testing.T) {
	t.Parallel()

	wantPatterns := map[string]string{
		"secret-exfil-url-blocked":      patternText("core DLP match: AWS Access ID (critical)"),
		"poisoned-ticket-webhook-exfil": patternText("request body contains secret: Private ", "Key Header"),
		"poisoned-readme-key-paste":     patternText("request body contains secret: OpenAI API ", "Key"),
		"hostile-page-session-keys":     patternText("request body contains secret: JWT Token"),
	}

	for _, s := range DefaultScenarios() {
		wantPattern, ok := wantPatterns[s.ID]
		if !ok {
			continue
		}
		s := s
		t.Run(s.ID, func(t *testing.T) {
			t.Parallel()

			eng := newTestEngine(t)
			got, err := eng.Capture(s)
			if err != nil {
				t.Fatalf("Capture(%s): %v", s.ID, err)
			}
			decisive := decisiveReceipt(got.Receipts, s.ExpectedVerdict)
			if decisive == nil {
				t.Fatalf("no receipt with expected verdict %q; got verdicts %v",
					s.ExpectedVerdict, verdictsOf(got.Receipts))
			}
			if decisive.ActionRecord.Layer != s.ExpectedLayer {
				t.Fatalf("decisive layer=%q want %q", decisive.ActionRecord.Layer, s.ExpectedLayer)
			}
			if decisive.ActionRecord.Pattern != wantPattern {
				t.Fatalf("decisive pattern=%q want %q", decisive.ActionRecord.Pattern, wantPattern)
			}
		})
	}
}

func TestForwardBodyDLPSecretDrivenNotBlanketBlock(t *testing.T) {
	t.Parallel()

	cases := []struct {
		scenarioID string
		target     string
		secretBody string
	}{
		{
			scenarioID: "poisoned-ticket-webhook-exfil",
			target:     syntheticHTTPSURL(synthTicketWebhookHost, synthTicketWebhookPath),
			secretBody: poisonedTicketWebhookBody(),
		},
		{
			scenarioID: "poisoned-readme-key-paste",
			target:     syntheticHTTPSURL(synthPasteHost, synthPastePath),
			secretBody: poisonedReadmePasteBody(),
		},
		{
			scenarioID: "hostile-page-session-keys",
			target:     syntheticHTTPSURL(synthSessionSinkHost, synthSessionKeysPath),
			secretBody: hostilePageSessionKeysBody(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.scenarioID, func(t *testing.T) {
			t.Parallel()

			h, closeProxy := testProxyHandler(t, scenarioByID(t, tc.scenarioID))
			defer closeProxy()

			ctx, cancel := context.WithTimeout(context.Background(), captureTimeout)
			defer cancel()

			secretResp := forwardPostThrough(ctx, h, tc.target, tc.secretBody)
			if secretResp.Code != http.StatusForbidden {
				t.Fatalf("secret POST status = %d, want %d", secretResp.Code, http.StatusForbidden)
			}

			benignResp := forwardPostThrough(ctx, h, tc.target, `{"note":"benign lab control body","contains_secret":false}`)
			if benignResp.Code == http.StatusForbidden {
				t.Fatalf("benign POST was blanket-blocked at same destination: status=%d reason=%q body=%q",
					benignResp.Code, benignResp.Header().Get("X-Pipelock-Block-Reason"), benignResp.Body.String())
			}
			if reason := benignResp.Header().Get("X-Pipelock-Block-Reason"); reason != "" {
				t.Fatalf("benign POST returned Pipelock block reason %q with status %d", reason, benignResp.Code)
			}
			t.Logf("benign control to %s status=%d (not a Pipelock body_dlp block)", tc.target, benignResp.Code)
		})
	}
}

// TestCapture_RedactsSecretBeforeSign proves the secret-exfil scenario never
// publishes the raw synthetic key: redaction runs before signing, so the signed
// receipt target carries a placeholder, not the key.
func TestCapture_RedactsSecretBeforeSign(t *testing.T) {
	t.Parallel()

	var scenario Scenario
	for _, s := range DefaultScenarios() {
		if s.ID == "secret-exfil-url-blocked" {
			scenario = s
		}
	}

	eng := newTestEngine(t)
	got, err := eng.Capture(scenario)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}

	key := SyntheticAWSKey()
	for _, r := range got.Receipts {
		if strings.Contains(r.ActionRecord.Target, key) {
			t.Fatalf("raw synthetic key leaked into signed receipt target: %q", r.ActionRecord.Target)
		}
	}
}

func decisiveReceipt(receipts []receipt.Receipt, verdict string) *receipt.Receipt {
	for i := range receipts {
		if receipts[i].ActionRecord.Verdict == verdict {
			return &receipts[i]
		}
	}
	return nil
}

func verdictsOf(receipts []receipt.Receipt) []string {
	out := make([]string, 0, len(receipts))
	for _, r := range receipts {
		out = append(out, r.ActionRecord.Verdict)
	}
	return out
}

func scenarioByID(t *testing.T, id string) Scenario {
	t.Helper()
	for _, s := range DefaultScenarios() {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("scenario %q not found", id)
	return Scenario{}
}

func testProxyHandler(t *testing.T, s Scenario) (http.Handler, func()) {
	t.Helper()

	cfg, err := labConfig(s)
	if err != nil {
		t.Fatalf("labConfig(%s): %v", s.ID, err)
	}
	sc := scanner.New(cfg)
	p, err := proxy.New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		sc.Close()
		t.Fatalf("proxy.New(%s): %v", s.ID, err)
	}
	return p.Handler(), func() {
		p.Close()
		sc.Close()
	}
}

func patternText(parts ...string) string {
	return strings.Join(parts, "")
}
