// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCredentialAudienceHosts_BodyAndHeaderCarriers(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	for _, tc := range credentialAudienceCarrierCases() {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"credential":"` + tc.credential + `"}`
			var bodyAllows []scanner.CredentialAudienceAllow
			_, bodyResult := scanRequestBody(context.Background(), BodyScanRequest{
				Body:                      strings.NewReader(body),
				ContentType:               "application/json",
				MaxBytes:                  cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner:                   sc,
				Target:                    tc.target,
				AudienceSurface:           "body",
				OnCredentialAudienceAllow: func(allow scanner.CredentialAudienceAllow) { bodyAllows = append(bodyAllows, allow) },
			})
			if !bodyResult.Clean || len(bodyAllows) != 1 || bodyAllows[0].PatternName != tc.pattern {
				t.Fatalf("body audience result=%+v allows=%+v", bodyResult, bodyAllows)
			}

			headers := http.Header{"Authorization": []string{"Bearer " + tc.credential}}
			var headerAllows []scanner.CredentialAudienceAllow
			headerResult := scanRequestHeadersForTargetWithAudience(context.Background(), headers, cfg, sc, tc.target, nil, func(allow scanner.CredentialAudienceAllow) { headerAllows = append(headerAllows, allow) })
			if headerResult != nil && !headerResult.Clean {
				t.Fatalf("header audience result=%+v", headerResult)
			}
			if len(headerAllows) != 1 || headerAllows[0].PatternName != tc.pattern {
				t.Fatalf("header audience allows=%+v", headerAllows)
			}

			_, blockedBody := scanRequestBody(context.Background(), BodyScanRequest{
				Body: strings.NewReader(body), ContentType: "application/json", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
				Scanner: sc, Target: "https://api.vendor.example/v1",
			})
			if blockedBody.Clean {
				t.Fatal("non-audience body allowed")
			}
			blockedHeader := scanRequestHeadersForTarget(context.Background(), headers, cfg, sc, "https://api.vendor.example/v1")
			if blockedHeader == nil || blockedHeader.Clean {
				t.Fatal("non-audience header allowed")
			}
		})
	}
}

func TestCredentialAudienceHosts_WebSocketFrameAndFragmentedDirectText(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	key := "sk-" + "proj-" + strings.Repeat("a", 24)
	p := &Proxy{logger: audit.NewNop(), metrics: metrics.New()}
	relay := &wsRelay{scanner: sc, proxy: p, cfg: cfg, targetURL: "wss://api.openai.com/v1/realtime", hostname: "api.openai.com", path: "/v1/realtime", maxMsg: 1 << 20}
	relay.resetCredentialAudienceAllows()

	_, bodyResult := relay.scanClientMessageBody(context.Background(), []byte(`{"credential":"`+key+`"}`))
	if !bodyResult.Clean {
		t.Fatalf("WebSocket body path blocked audience credential: %+v", bodyResult)
	}
	if relay.scanClientText(context.Background(), audit.NewNop(), []byte(key)) {
		t.Fatal("WebSocket direct text path blocked audience credential")
	}
	// The complete match arrives across two frame-like pieces. This exercises
	// the direct fragmented-text path, which has no independent authority.
	if relay.scanClientCrossMessageText(context.Background(), audit.NewNop(), []byte(key[:10]), []byte(key[10:])) {
		t.Fatal("WebSocket fragmented direct text path blocked audience credential")
	}
}

func TestCredentialAudienceHosts_CorePatternStillBlocksAtAudience(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	core := "AKIA" + "IOSFODNN7EXAMPLE"
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body: strings.NewReader(`{"credential":"` + core + `"}`), ContentType: "application/json", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner: sc, Target: "https://api.openai.com/v1",
	})
	if result.Clean {
		t.Fatal("core credential was allowed at an audience host")
	}
}

func TestCredentialAudienceHosts_RuntimeBodyKnobsCannotBypassMismatch(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.DisablePatterns = []string{"OpenAI API Key"}
	cfg.RequestBodyScanning.PatternActions = map[string]string{"OpenAI API Key": config.ActionWarn}
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	key := "sk-" + "proj-" + strings.Repeat("a", 24)
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader(`{"credential":"` + key + `"}`),
		ContentType:     "application/json",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
		Target:          "https://api.vendor.example/v1",
		Action:          config.ActionBlock,
		DisablePatterns: cfg.RequestBodyScanning.DisablePatterns,
		PatternActions:  cfg.RequestBodyScanning.PatternActions,
	})
	if result.Clean || result.Action != config.ActionBlock {
		t.Fatalf("runtime body knobs weakened audience mismatch: %+v", result)
	}
}

type credentialAudienceCarrierCase struct {
	name       string
	pattern    string
	credential string
	target     string
}

func credentialAudienceCarrierCases() []credentialAudienceCarrierCase {
	return []credentialAudienceCarrierCase{
		{name: "OpenAI", pattern: "OpenAI API Key", credential: "sk-" + "proj-" + strings.Repeat("a", 24), target: "https://api.openai.com/v1/responses"},
		{name: "Anthropic", pattern: "Anthropic API Key", credential: "sk-" + "ant-" + strings.Repeat("a", 24), target: "https://api.anthropic.com/v1/messages"},
		{name: "Discord", pattern: "Discord Bot Token", credential: "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27), target: "https://discord.com/api/v10"},
	}
}
