// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScan_CredentialAudienceHosts_AllBuiltInsURL(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	for _, test := range credentialAudienceURLCases() {
		t.Run(test.pattern, func(t *testing.T) {
			result := s.Scan(context.Background(), test.audienceURL+"?credential="+test.credential)
			if !result.Allowed {
				t.Fatalf("audience URL blocked: %s", result.Reason)
			}
			assertCredentialAudienceAllow(t, result, test.pattern, "url", test.destination)

			blocked := s.Scan(context.Background(), "https://api.vendor.example/v1?credential="+test.credential)
			if blocked.Allowed {
				t.Fatal("non-audience URL allowed")
			}
			if !strings.Contains(blocked.Reason, test.pattern) {
				t.Fatalf("non-audience reason = %q, want %q", blocked.Reason, test.pattern)
			}
			if len(blocked.CredentialAudienceAllows) != 0 {
				t.Fatalf("non-audience allow records = %#v", blocked.CredentialAudienceAllows)
			}
			if len(blocked.CredentialAudienceMismatches) != 1 || blocked.CredentialAudienceMismatches[0].PatternName != test.pattern || blocked.CredentialAudienceMismatches[0].Destination != "api.vendor.example" {
				t.Fatalf("non-audience mismatch = %#v", blocked.CredentialAudienceMismatches)
			}
		})
	}
}

func TestScan_CredentialAudienceHosts_FailsClosedForLookalikesAndCore(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	openAIKey := "sk-" + "proj-" + strings.Repeat("a", 24)
	for _, target := range []string{
		"https://api.openai.com.evil.example/v1?credential=",
		"https://openai.com.attacker.example/v1?credential=",
		"https://xopenai.com/v1?credential=",
	} {
		result := s.Scan(context.Background(), target+openAIKey)
		if result.Allowed {
			t.Fatalf("lookalike target %q allowed", target)
		}
		if len(result.CredentialAudienceAllows) != 0 {
			t.Fatalf("lookalike target %q emitted allowance %#v", target, result.CredentialAudienceAllows)
		}
	}

	core := s.Scan(context.Background(), "https://api.openai.com/v1?credential="+"AKIA"+strings.Repeat("A", 16))
	if core.Allowed {
		t.Fatal("core pattern at an audience host allowed")
	}
	if core.Scanner != ScannerCoreDLP {
		t.Fatalf("core pattern scanner = %q, want %q", core.Scanner, ScannerCoreDLP)
	}
}

func TestFilterTextDLPMatchesForDestination_CanonicalAndFailClosed(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	key := "sk-" + "proj-" + strings.Repeat("a", 24)
	matches := s.ScanTextForDLP(context.Background(), key).Matches
	if len(matches) != 1 {
		t.Fatalf("text matches = %#v, want one OpenAI match", matches)
	}
	allowed, records := s.FilterTextDLPMatchesForDestination(matches, "https://API.OPENAI.COM./v1", "body")
	if len(allowed) != 0 {
		t.Fatalf("canonical audience match retained %#v", allowed)
	}
	if len(records) != 1 || records[0].Destination != "api.openai.com" || records[0].Surface != "body" {
		t.Fatalf("canonical audience record = %#v", records)
	}

	for _, target := range []string{"not a URL", "https://api.openai.com@evil.example/v1"} {
		retained, records := s.FilterTextDLPMatchesForDestination(matches, target, "body")
		if len(retained) != 1 || len(records) != 0 {
			t.Fatalf("target %q = retained %#v, records %#v; parse failure must block", target, retained, records)
		}
	}
}

func credentialAudienceTestConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 100
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 100
	return cfg
}

type credentialAudienceURLCase struct {
	pattern     string
	credential  string
	audienceURL string
	destination string
}

func credentialAudienceURLCases() []credentialAudienceURLCase {
	return []credentialAudienceURLCase{
		{"Anthropic API Key", "sk-" + "ant-" + strings.Repeat("a", 24), "https://api.anthropic.com/v1", "api.anthropic.com"},
		{"OpenAI API Key", "sk-" + "proj-" + strings.Repeat("a", 24), "https://api.openai.com/v1", "api.openai.com"},
		{"OpenAI Service Key", "sk-" + "svcacct-" + strings.Repeat("a", 24), "https://api.openai.com/v1", "api.openai.com"},
		{"Fireworks API Key", "fw_" + strings.Repeat("a", 22), "https://api.fireworks.ai/inference/v1", "api.fireworks.ai"},
		{"LLM Router API Key", "sk-or-v1-" + strings.Repeat("a", 24), "https://openrouter.ai/api/v1", "openrouter.ai"},
		{"Answer Engine API Key", "pplx-" + strings.Repeat("a", 24), "https://api.perplexity.ai", "api.perplexity.ai"},
		{"Web Research API Key", "tvly-" + strings.Repeat("a", 24), "https://api.tavily.com", "api.tavily.com"},
		{"Google API Key", "AIza" + strings.Repeat("a", 35), "https://generativelanguage.googleapis.com", "generativelanguage.googleapis.com"},
		{"Hugging Face Token", "hf_" + strings.Repeat("a", 34), "https://api.huggingface.co", "api.huggingface.co"},
		{"Databricks Token", "dapi" + strings.Repeat("a", 32), "https://workspace.databricks.com", "workspace.databricks.com"},
		{"Replicate API Token", "r8_" + strings.Repeat("a", 40), "https://api.replicate.com", "api.replicate.com"},
		{"Together AI Key", "tok_" + strings.Repeat("a", 40), "https://api.together.ai", "api.together.ai"},
		{"Pinecone API Key", "pcsk_" + strings.Repeat("a", 36), "https://api.pinecone.io", "api.pinecone.io"},
		{"Groq API Key", "gsk_" + strings.Repeat("a", 48), "https://api.groq.com", "api.groq.com"},
		{"xAI API Key", "xai-" + strings.Repeat("a", 80), "https://api.x.ai", "api.x.ai"},
		{"Discord Bot Token", "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27), "https://discord.com/api/v10", "discord.com"},
	}
}

func assertCredentialAudienceAllow(t *testing.T, result Result, pattern, surface, destination string) {
	t.Helper()
	if len(result.CredentialAudienceAllows) != 1 {
		t.Fatalf("audience allow records = %#v, want one", result.CredentialAudienceAllows)
	}
	got := result.CredentialAudienceAllows[0]
	if got.PatternName != pattern || got.Surface != surface || got.Destination != destination {
		t.Fatalf("audience allow = %#v, want pattern=%q surface=%q destination=%q", got, pattern, surface, destination)
	}
}
