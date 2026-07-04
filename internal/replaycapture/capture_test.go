// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
