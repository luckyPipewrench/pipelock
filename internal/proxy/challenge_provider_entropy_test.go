// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A bot-verification challenge posts encrypted, per-challenge data to the
// provider's own host. It reads as high entropy by construction and used to
// escalate a browser session until the challenge could never complete. The
// shipped challenge hosts are exempt from the entropy heuristics only, in
// addition to an operator's own lists; DLP still runs.
func TestChallengeProviderEntropyExemption(t *testing.T) {
	const challengeURL = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/flow/ov1/x"
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	logger, _ := audit.New("json", "stdout", "", false, false)
	m := metrics.New()

	budget := func(target string, exempt []string) ceeResult {
		et := scanner.NewEntropyTracker(1.0, 300)
		defer et.Close()
		return ceeAdmit(context.Background(), ceeAdmitOptions{
			Outbound: []byte("x7k9mQ2pR4wL8nJ5vB3cT6yH0"), TargetURL: target,
			Agent: testCEEAgent, ClientIP: testCEEClientIP, RequestID: testCEERequestID,
			Config: config.CrossRequestDetection{EntropyBudget: config.CrossRequestEntropyBudget{
				Enabled: true, BitsPerWindow: 1.0, WindowMinutes: 5, Action: config.ActionBlock, ExemptDomains: exempt,
			}},
			Entropy: et, Logger: logger, Metrics: m,
		})
	}
	t.Run("budget skips the challenge host beside an operator list", func(t *testing.T) {
		if r := budget(challengeURL, []string{"api.vendor.example"}); r.Blocked || r.EntropyHit {
			t.Fatalf("challenge host must not spend the entropy budget: %+v", r)
		}
	})
	for _, target := range []string{
		"https://collector.evil.test/cdn-cgi/challenge-platform/h/b/flow",
		"https://challenges.cloudflare.com.evil.test/x",
		"https://evilchallenges.cloudflare.com.example/x",
	} {
		t.Run("budget still applies to "+target, func(t *testing.T) {
			if r := budget(target, []string{"api.vendor.example"}); !r.Blocked {
				t.Fatalf("non-challenge host must spend the budget: %+v", r)
			}
		})
	}

	t.Run("body entropy exclusion includes the challenge host beside an operator list", func(t *testing.T) {
		c := config.Defaults()
		c.RequestBodyScanning.ContentEntropyExclusions = []string{"api.vendor.example"}
		var req BodyScanRequest
		applyContentEntropyConfig(&req, c)
		found := map[string]bool{}
		for _, h := range req.ContentEntropyExclusions {
			found[h] = true
		}
		if !found["challenges.cloudflare.com"] || !found["api.vendor.example"] {
			t.Fatalf("exclusions = %v", req.ContentEntropyExclusions)
		}
		if got := len(config.ShippedChallengeProviderHosts()); got != 1 {
			t.Fatalf("shipped challenge hosts changed without updating this test: %d", got)
		}
	})

	t.Run("fragment DLP still fires on the challenge host", func(t *testing.T) {
		et := scanner.NewEntropyTracker(1.0, 300)
		defer et.Close()
		fb := scanner.NewFragmentBuffer(65536, 1000, 300)
		defer fb.Close()
		ceeCfg := config.CrossRequestDetection{
			Action:             config.ActionBlock,
			EntropyBudget:      config.CrossRequestEntropyBudget{Enabled: true, BitsPerWindow: 1.0, WindowMinutes: 5, Action: config.ActionBlock},
			FragmentReassembly: config.CrossRequestFragments{Enabled: true, MaxBufferBytes: 65536, WindowMinutes: 5},
		}
		opts := ceeAdmitOptions{TargetURL: challengeURL, Agent: testCEEAgent, ClientIP: testCEEClientIP, Config: ceeCfg, Entropy: et, Fragments: fb, Scanner: sc, Logger: logger, Metrics: m}
		opts.Outbound, opts.RequestID = []byte(testCEEAWSKeyPrefix), "req-1"
		if r := ceeAdmit(context.Background(), opts); r.Blocked {
			t.Fatal("first fragment should not block")
		}
		opts.Outbound, opts.RequestID = []byte(testCEEAWSKeySuffix), "req-2"
		if r := ceeAdmit(context.Background(), opts); !r.Blocked || !r.FragmentHit {
			t.Fatalf("a split secret to the challenge host must still block: %+v", r)
		}
	})
}

func TestChallengeProviderBodyEntropyIsExemptButDLPIsNot(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.ContentEntropyEnabled = true
	cfg.RequestBodyScanning.ContentEntropyAction = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyThreshold = 4.5
	cfg.RequestBodyScanning.ContentEntropyMinLength = 32
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.ContentEntropyExclusions = []string{"api.vendor.example"}
	addBodyDLPTestPattern(cfg)
	opaque := `{"blob":"` + opaqueHighEntropyBodyValue() + `"}`

	for _, tc := range []struct {
		host        string
		body        string
		wantEntropy bool
		wantDLP     bool
	}{
		{"challenges.cloudflare.com", opaque, false, false},
		{"collector.evil.test", opaque, true, false},
		{"challenges.cloudflare.com.evil.test", opaque, true, false},
		{"challenges.cloudflare.com", `{"k":"REQDLPTEST-ABCDEF123456"}`, false, true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			req := contentEntropyBodyReq(t, cfg, tc.host, tc.body)
			defer req.Scanner.Close()
			_, result := scanRequestBody(context.Background(), req)
			if (result.EntropyFinding != nil) != tc.wantEntropy {
				t.Fatalf("%s entropy finding = %v, want %v", tc.host, result.EntropyFinding != nil, tc.wantEntropy)
			}
			if (len(result.DLPMatches) > 0) != tc.wantDLP {
				t.Fatalf("%s DLP matches = %v, want %v", tc.host, result.DLPMatches, tc.wantDLP)
			}
		})
	}
}

// A bot-verification challenge may read its own images byte for byte, so
// Pipelock does not strip metadata from a challenge provider's images. Type,
// size and parse checks still apply, and every other host is still stripped.
func TestChallengeProviderImagesKeepMetadata(t *testing.T) {
	cfg := config.Defaults()
	body := buildValidPNG([]byte("Description\x00challenge-data"))
	for _, tc := range []struct {
		host      string
		wantStrip bool
	}{
		{"challenges.cloudflare.com", false},
		{"cdn.vendor.example", true},
		{"challenges.cloudflare.com.evil.test", true},
		{"", true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			v := applyMediaPolicy(cfg, "image/png", body, mediaPolicyOptions{host: tc.host})
			if v.Blocked {
				t.Fatalf("blocked: %s", v.BlockReason)
			}
			if stripped := !bytes.Equal(v.Body, body); stripped != tc.wantStrip {
				t.Fatalf("host %q stripped = %v, want %v", tc.host, stripped, tc.wantStrip)
			}
		})
	}
	oversize := config.Defaults()
	oversize.MediaPolicy.MaxImageBytes = 8
	if v := applyMediaPolicy(oversize, "image/png", body, mediaPolicyOptions{host: "challenges.cloudflare.com"}); !v.Blocked {
		t.Fatal("size limits must still apply to a challenge provider")
	}
}
