// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
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

// A carrier header with many fields is left unscrubbed rather than rescanned
// field by field, so the joined scan keeps the match and the request blocks.
func TestScrubAuthorizedEncodedFieldsBoundsFieldCount(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	basic := func(user, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
	}
	gitTarget := "https://gitlab.com/group/project.git/info/refs?service=git-upload-pack"
	within := basic("oauth2", "glpat-"+strings.Repeat("c", 20))
	if got := s.scrubAuthorizedEncodedFields(within, gitTarget, credentialAudienceAuthorizationBasicSurface); got == within {
		t.Fatalf("control: allowed git Basic credential was not scrubbed: %q", got)
	}
	// A Google token has no Basic carrier, so Basic keeps it visible.
	google := basic("oauth2", "ya29."+strings.Repeat("a", 24))
	if got := s.scrubAuthorizedEncodedFields(google, "https://gmail.googleapis.com/gmail/v1/users/me/profile", credentialAudienceAuthorizationBasicSurface); got != google {
		t.Fatalf("Google token in Basic was scrubbed: %q", got)
	}
	padded := within + strings.Repeat(" x", maxAuthorizedEncodedFields)
	if got := s.scrubAuthorizedEncodedFields(padded, gitTarget, credentialAudienceAuthorizationBasicSurface); got != padded {
		t.Fatalf("over-limit header was rescanned and scrubbed: %q", got)
	}
}

func TestGoogleOAuthToken_CredentialAudience(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()
	token := "ya29." + strings.Repeat("a", 24)
	matches := s.ScanTextForDLP(context.Background(), token).Matches
	if len(matches) != 1 || matches[0].PatternName != "Google OAuth Token" {
		t.Fatalf("synthetic Google token did not match once: %#v", matches)
	}
	header := "Bearer " + token
	if got := s.ScrubAuthorizedCredentialFromJoinedHeaders("Authorization", header, "https://gmail.googleapis.com/gmail/v1/users/me/profile"); strings.Contains(got, token) {
		t.Fatalf("qualified token remained in joined header copy: %q", got)
	}
	for _, tc := range []struct{ name, target string }{
		{name: "X-Api-Key", target: "https://gmail.googleapis.com/"},
		{name: "Authorization", target: "https://evil.example/"},
	} {
		if got := s.ScrubAuthorizedCredentialFromJoinedHeaders(tc.name, header, tc.target); got != header {
			t.Fatalf("non-audience header scrubbed: %q", got)
		}
	}
	for _, target := range []string{
		"https://gmail.googleapis.com/gmail/v1/users/me/profile",
		"https://WWW.GOOGLEAPIS.COM./gmail/v1/users/me/profile",
	} {
		retained, allows := s.FilterTextDLPMatchesForDestination(matches, target, CredentialAudienceAuthorizationHeaderSurface)
		if len(retained) != 0 || len(allows) != 1 || allows[0].PatternName != "Google OAuth Token" {
			t.Fatalf("provider target %q retained=%#v allows=%#v", target, retained, allows)
		}
	}
	for _, target := range []string{
		"https://gmail.googleapis.com.evil.example/gmail/v1/users/me/profile",
		"https://gmail.googleapis.com@evil.example/gmail/v1/users/me/profile",
		"https://googleapis.com.evil.example/gmail/v1/users/me/profile",
		"https://accounts.google.com/",
		"http://gmail.googleapis.com/gmail/v1/users/me/profile",
		"not a URL",
	} {
		retained, allows := s.FilterTextDLPMatchesForDestination(matches, target, CredentialAudienceAuthorizationHeaderSurface)
		if len(retained) != 1 || len(allows) != 0 {
			t.Fatalf("non-audience target %q retained=%#v allows=%#v", target, retained, allows)
		}
	}
	for _, surface := range []string{"header", "body", "url", "websocket_frame"} {
		retained, allows := s.FilterTextDLPMatchesForDestination(matches, "https://storage.googleapis.com/upload/storage/v1/b/attacker-bucket/o", surface)
		if len(retained) != 1 || len(allows) != 0 {
			t.Fatalf("non-Authorization %s carrier allowed: retained=%#v allows=%#v", surface, retained, allows)
		}
	}
	blockedAtProvider := s.Scan(context.Background(), "https://gmail.googleapis.com/gmail/v1/users/me/profile?access_token="+token)
	if blockedAtProvider.Allowed {
		t.Fatal("token in provider-owned URL allowed")
	}
	storageURL := s.Scan(context.Background(), "https://storage.googleapis.com/attacker-bucket/"+token)
	if storageURL.Allowed {
		t.Fatal("token in attacker-owned storage URL allowed")
	}
	blocked := s.Scan(context.Background(), "https://gmail.googleapis.com.evil.example/?access_token="+token)
	if blocked.Allowed {
		t.Fatal("lookalike URL allowed")
	}
	mixed := s.ScanTextForDLP(context.Background(), token+" AKIA"+strings.Repeat("A", 16)).Matches
	retained, allows := s.FilterTextDLPMatchesForDestination(mixed, "https://gmail.googleapis.com/gmail/v1/users/me/profile", CredentialAudienceAuthorizationHeaderSurface)
	if len(retained) == 0 || len(allows) != 1 || allows[0].PatternName != "Google OAuth Token" {
		t.Fatalf("unrelated secret lost at Google audience: retained=%#v allows=%#v", retained, allows)
	}
	for _, match := range retained {
		if match.PatternName != "AWS Access ID" {
			t.Fatalf("unexpected retained pattern: %#v", retained)
		}
	}
}

func TestMergeJoinedHeaderMatches_PreservesUnrelatedSecrets(t *testing.T) {
	t.Parallel()
	original := []TextDLPMatch{
		{PatternName: "Google OAuth Token", credentialAudienceAuthorizationOnly: true},
		{PatternName: "AWS Access ID"},
	}
	scrubbed := []TextDLPMatch{
		{PatternName: "Google OAuth Token", credentialAudienceAuthorizationOnly: true},
		{PatternName: "GitHub Token"},
	}
	merged := MergeJoinedHeaderMatches(original, scrubbed)
	if len(merged) != 2 || merged[0].PatternName != "AWS Access ID" || merged[1].PatternName != "Google OAuth Token" {
		t.Fatalf("joined-header matches = %#v; unrelated original match must survive while authorization-only match comes from scrubbed copy", merged)
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

// TestScan_CredentialAudienceHosts_SlackCoreAndAppToken proves a credential
// whose issuing authority is slack.com is allowed there over an encrypted
// scheme, on both the core-floor bot/user token and the non-core app-level
// token, while every other destination, scheme, and lookalike keeps the match
// and blocks. Slack Token is a core pattern, so this also proves a compiled
// audience now attaches to the immutable floor at its own authority.
func TestScan_CredentialAudienceHosts_SlackCoreAndAppToken(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	// Confirm the premise the fix rests on: Slack Token is still on the
	// immutable core floor and still carries the compiled audience. If a later
	// change drops it from core, this test would otherwise silently pass for the
	// wrong reason.
	if !config.IsCoreDLPPatternName("Slack Token") {
		t.Fatal("Slack Token must remain a core-floor pattern")
	}
	if config.IsCoreDLPPatternName("Slack App Token") {
		t.Fatal("Slack App Token is not a core-floor pattern")
	}

	xoxb := "xoxb-" + strings.Repeat("A", 20)                                     // core bot token
	xoxp := "xoxp-" + strings.Repeat("A", 20)                                     // core user token
	xapp := "xapp-1-" + strings.Repeat("A", 12) + "-2-" + strings.Repeat("b", 16) // non-core app-level token

	tokens := []struct {
		pattern string
		value   string
	}{
		{"Slack Token", xoxb},
		{"Slack App Token", xapp},
	}

	for _, tok := range tokens {
		tok := tok
		t.Run(tok.pattern, func(t *testing.T) {
			t.Parallel()
			matches := s.ScanTextForDLP(context.Background(), tok.value).Matches
			if len(matches) != 1 || matches[0].PatternName != tok.pattern {
				t.Fatalf("scan matches = %#v, want one %q", matches, tok.pattern)
			}

			// Allowed at the issuing authority over an encrypted scheme, on the
			// header and body surfaces the tokens actually travel on. Failure
			// direction: a retained match here blocks a legitimate Slack call.
			for _, surface := range []string{"header", "body"} {
				allowed, records := s.FilterTextDLPMatchesForDestination(matches, "https://slack.com/api/auth.test", surface)
				if len(allowed) != 0 {
					t.Fatalf("%s: audience match retained %#v", surface, allowed)
				}
				if len(records) != 1 || records[0].PatternName != tok.pattern || records[0].Destination != "slack.com" || records[0].Surface != surface {
					t.Fatalf("%s: audience record = %#v", surface, records)
				}
			}

			// Fail closed everywhere else. Failure direction: an allow on any of
			// these would leak the credential off its issuing authority.
			blockers := []struct {
				name   string
				target string
			}{
				{"unrelated https host", "https://api.vendor.example/v1"},
				{"exact-host subdomain is not the authority", "https://api.slack.com/api/auth.test"},
				{"suffix lookalike", "https://slack.com.evil.example/api/auth.test"},
				{"prefix lookalike", "https://xslack.com/api/auth.test"},
				{"cleartext http keeps the match", "http://slack.com/api/auth.test"},
				{"userinfo-bearing target is malformed", "https://slack.com@evil.example/api"},
				{"unparseable target", "not a url"},
			}
			for _, b := range blockers {
				retained, records := s.FilterTextDLPMatchesForDestination(matches, b.target, "header")
				if len(retained) != 1 {
					t.Fatalf("%s (%q): match dropped, retained=%#v", b.name, b.target, retained)
				}
				if len(records) != 0 {
					t.Fatalf("%s (%q): emitted allow %#v", b.name, b.target, records)
				}
			}
		})
	}

	// Slack's hosted MCP server accepts user tokens but not app-level Socket
	// Mode tokens. Keep those two credential audiences distinct and cover both
	// carrier surfaces used by the request scanner.
	xoxpMatches := s.ScanTextForDLP(context.Background(), xoxp).Matches
	for _, surface := range []string{"header", "body"} {
		retained, records := s.FilterTextDLPMatchesForDestination(xoxpMatches, "https://mcp.slack.com/mcp", surface)
		if len(retained) != 0 || len(records) != 1 || records[0].PatternName != "Slack Token" || records[0].Destination != "mcp.slack.com" || records[0].Surface != surface {
			t.Fatalf("%s: Slack user token MCP audience retained=%#v records=%#v", surface, retained, records)
		}
	}
	xappMatches := s.ScanTextForDLP(context.Background(), xapp).Matches
	retained, records := s.FilterTextDLPMatchesForDestination(xappMatches, "https://mcp.slack.com/mcp", "header")
	if len(retained) != 1 || len(records) != 0 {
		t.Fatalf("Slack App Token was allowed at MCP host: retained=%#v records=%#v", retained, records)
	}
	for _, target := range []string{
		"http://mcp.slack.com/mcp",
		"https://mcp.slack.com.evil.example/mcp",
		"https://xmcp.slack.com/mcp",
		"https://mcp.slack.com@evil.example/mcp",
	} {
		retained, records = s.FilterTextDLPMatchesForDestination(xoxpMatches, target, "header")
		if len(retained) != 1 || len(records) != 0 {
			t.Fatalf("Slack MCP lookalike %q allowed: retained=%#v records=%#v", target, retained, records)
		}
	}

	// The URL core floor is intentionally unchanged: a core credential placed in
	// a URL query is blocked even at slack.com, because a URL leaks the token
	// into logs and history in ways a header does not. Slack never sends tokens
	// in URLs, so this boundary does not affect the integration.
	urlBlocked := s.Scan(context.Background(), "https://slack.com/api/auth.test?token="+xoxb)
	if urlBlocked.Allowed {
		t.Fatal("core Slack Token in a URL query allowed; the URL core floor must stay strict")
	}
	if urlBlocked.Scanner != ScannerCoreDLP {
		t.Fatalf("URL Slack Token block scanner = %q, want %q", urlBlocked.Scanner, ScannerCoreDLP)
	}
}

func TestFilterTextDLPMatchesForDestination_UsesMatchProvenance(t *testing.T) {
	t.Parallel()

	withoutConfiguredDefaults := credentialAudienceTestConfig()
	withoutConfiguredDefaults.DLP.Patterns = nil
	coreOnly := MustNew(withoutConfiguredDefaults)
	defer coreOnly.Close()

	slackToken := strings.Join([]string{"xoxb", "123456789012", "123456789012", strings.Repeat("a", 24)}, "-")
	coreMatches := coreOnly.ScanTextForDLP(context.Background(), slackToken).Matches
	retained, allows := coreOnly.FilterTextDLPMatchesForDestination(coreMatches, "https://slack.com:443/api/auth.test", "header")
	if len(retained) != 0 || len(allows) != 1 || allows[0].PatternName != "Slack Token" {
		t.Fatalf("core-only Slack audience retained=%#v allows=%#v", retained, allows)
	}
	userToken := "xoxp-" + strings.Repeat("a", 24)
	userMatches := coreOnly.ScanTextForDLP(context.Background(), userToken).Matches
	retained, allows = coreOnly.FilterTextDLPMatchesForDestination(userMatches, "https://mcp.slack.com/mcp", "header")
	if len(retained) != 0 || len(allows) != 1 || allows[0].PatternName != "Slack Token" || allows[0].Destination != "mcp.slack.com" {
		t.Fatalf("core-only Slack MCP audience retained=%#v allows=%#v", retained, allows)
	}

	customCfg := credentialAudienceTestConfig()
	customCfg.DLP.Patterns = []config.DLPPattern{{
		Name:     "Slack Token",
		Regex:    `custom-[A-Za-z]{20}`,
		Severity: config.SeverityCritical,
	}}
	custom := MustNew(customCfg)
	defer custom.Close()

	customMatches := custom.ScanTextForDLP(context.Background(), "custom-abcdefghijklmnopqrst").Matches
	retained, allows = custom.FilterTextDLPMatchesForDestination(customMatches, "https://slack.com/api/auth.test", "header")
	if len(retained) != 1 || len(allows) != 0 {
		t.Fatalf("custom same-name pattern inherited core audience: retained=%#v allows=%#v", retained, allows)
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

// TestFilterTextDLPMatchesForDestination_OtherCoreCredentialsStayBlocked proves
// the core-floor audience exception is pattern-specific. Every other immutable
// credential still blocks at Slack, at a host that looks like its own issuer,
// and on an unrelated host. The Slack token in the same text is the control:
// if the scanner blocked everything, this test would not show that the floor
// stayed closed for the other classes.
func TestFilterTextDLPMatchesForDestination_OtherCoreCredentialsStayBlocked(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	slack := "xoxb-" + strings.Repeat("a", 24)
	cores := []struct {
		name  string
		value string
		host  string
	}{
		{name: "AWS Access ID", value: "AKIA" + "ZZZZZZZZZZZZZZZZ", host: "https://sts.amazonaws.com/"},
		{name: "GitHub Token", value: "ghp_" + strings.Repeat("a", 36), host: "https://github.com/"},
		{name: "GitHub Fine-Grained PAT", value: "github_pat_" + strings.Repeat("a", 36), host: "https://github.com/"},
		{name: "GitLab PAT", value: "glpat-" + strings.Repeat("a", 20), host: "https://gitlab.com/"},
		{name: "Private Key Header", value: "-----BEGIN " + "PRIVATE KEY-----", host: "https://slack.com/api/files.upload"},
	}
	for _, core := range cores {
		t.Run(core.name, func(t *testing.T) {
			t.Parallel()
			for _, surface := range []string{"header", "body"} {
				matches := s.ScanTextForDLP(context.Background(), core.value).Matches
				for _, target := range []string{core.host, "https://slack.com/api/auth.test", "https://api.vendor.example/v1"} {
					retained, records := s.FilterTextDLPMatchesForDestination(matches, target, surface)
					if !matchRetained(retained, core.name) {
						t.Fatalf("%s %s %q dropped core match, retained=%#v records=%#v", surface, core.name, target, retained, records)
					}
					if audienceAllowFor(records, core.name) {
						t.Fatalf("%s %s %q emitted an audience allow %#v", surface, core.name, target, records)
					}
				}
			}
			blocked := s.Scan(context.Background(), "https://slack.com/api/auth.test?credential="+urlQueryEscape(core.value))
			if blocked.Allowed {
				t.Fatalf("%s in a URL at slack.com was allowed", core.name)
			}
		})
	}

	// Same body, two credentials. Slack may be audience-eligible. The AWS key
	// must still be retained, or the allow would carry the other core secret.
	mixed := s.ScanTextForDLP(context.Background(), slack+" AKIA"+"ZZZZZZZZZZZZZZZZ").Matches
	retained, _ := s.FilterTextDLPMatchesForDestination(mixed, "https://slack.com/api/chat.postMessage", "body")
	if !matchRetained(retained, "AWS Access ID") {
		t.Fatalf("AWS key riding with a Slack token was dropped: %#v", retained)
	}
	slackOnly := s.ScanTextForDLP(context.Background(), slack).Matches
	kept, records := s.FilterTextDLPMatchesForDestination(slackOnly, "https://slack.com/api/auth.test", "header")
	if len(kept) != 0 || !audienceAllowFor(records, "Slack Token") {
		t.Fatalf("Slack control at its own authority retained=%#v records=%#v", kept, records)
	}
}

// TestFilterTextDLPMatchesForDestination_SlackHostIsExactAuthority checks the
// host comparisons that would hand a workspace token to someone else: a suffix,
// a label that merely contains the name, a different registrable domain, a
// userinfo trick, and an IDN lookalike. Case and a single trailing root dot are
// the same authority. A non-default port stays on that authority; the audience
// names the host, and the port was already checked to be a real port.
func TestFilterTextDLPMatchesForDestination_SlackHostIsExactAuthority(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceTestConfig())
	defer s.Close()

	slack := "xoxb-" + strings.Repeat("b", 24)
	matches := s.ScanTextForDLP(context.Background(), slack).Matches
	if len(matches) == 0 {
		t.Fatal("Slack token did not match")
	}

	cyrillicA := "sl" + string(rune(0x0430)) + "ck.com"
	cases := []struct {
		name  string
		url   string
		allow bool
		host  string
	}{
		{name: "suffix", url: "https://slack.com.evil.tld/api", allow: false},
		{name: "embedded label", url: "https://evil-slack.com/api", allow: false},
		{name: "prefix collision", url: "https://notslack.com/api", allow: false},
		{name: "subdomain", url: "https://hooks.slack.com/services/T/B/x", allow: false},
		{name: "mcp suffix", url: "https://mcp.slack.com.evil.tld/mcp", allow: false},
		{name: "userinfo on slack", url: "https://" + "user" + ":" + "pass" + "@slack.com/api", allow: false},
		{name: "userinfo swaps host", url: "https://slack.com@evil.tld/api", allow: false},
		{name: "cyrillic lookalike", url: "https://" + cyrillicA + "/api", allow: false},
		{name: "punycode lookalike", url: "https://xn--slck-6cd.com/api", allow: false},
		{name: "encoded dot", url: "https://slack.com%2eevil.tld/api", allow: false},
		{name: "uppercase", url: "https://SLACK.COM/api/auth.test", allow: true, host: "slack.com"},
		{name: "trailing dot", url: "https://slack.com./api/auth.test", allow: true, host: "slack.com"},
		{name: "non-default port", url: "https://slack.com:8443/api/auth.test", allow: true, host: "slack.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			retained, records := s.FilterTextDLPMatchesForDestination(matches, tc.url, "header")
			if tc.allow {
				if len(retained) != 0 || len(records) != 1 || records[0].Destination != tc.host {
					t.Fatalf("url %q retained=%#v records=%#v", tc.url, retained, records)
				}
				return
			}
			if len(retained) == 0 || len(records) != 0 {
				t.Fatalf("url %q allowed: retained=%#v records=%#v", tc.url, retained, records)
			}
		})
	}
}

// TestScanTextForDLP_CustomSameNameCannotBorrowCoreAudience is the fail-closed
// side of pattern-name dedup. A customized "Slack Token" pattern does not
// receive the compiled audience. When the real token and the customized text
// are in one body, dedup must not keep only the core match and then allow both.
func TestScanTextForDLP_CustomSameNameCannotBorrowCoreAudience(t *testing.T) {
	t.Parallel()
	cfg := credentialAudienceTestConfig()
	cfg.DLP.Patterns = []config.DLPPattern{{
		Name:     "Slack Token",
		Regex:    `custom-[A-Za-z]{20}`,
		Severity: config.SeverityCritical,
	}}
	s := MustNew(cfg)
	defer s.Close()

	slack := "xoxb-" + strings.Repeat("c", 24)
	custom := "custom-abcdefghijklmnopqrst"
	matches := s.ScanTextForDLP(context.Background(), custom+" "+slack).Matches
	retained, records := s.FilterTextDLPMatchesForDestination(matches, "https://slack.com/api/chat.postMessage", "body")
	if len(retained) == 0 || len(records) != 0 {
		t.Fatalf("custom same-name text borrowed the core audience: retained=%#v records=%#v", retained, records)
	}

	// The real token on its own still reaches Slack. This test must not pass
	// by blocking every Slack token.
	own := s.ScanTextForDLP(context.Background(), slack).Matches
	kept, allow := s.FilterTextDLPMatchesForDestination(own, "https://slack.com/api/auth.test", "header")
	if len(kept) != 0 || !audienceAllowFor(allow, "Slack Token") {
		t.Fatalf("real Slack token alone was blocked: retained=%#v records=%#v", kept, allow)
	}
}

func matchRetained(matches []TextDLPMatch, name string) bool {
	for _, match := range matches {
		if match.PatternName == name {
			return true
		}
	}
	return false
}

func audienceAllowFor(records []CredentialAudienceAllow, name string) bool {
	for _, record := range records {
		if record.PatternName == name {
			return true
		}
	}
	return false
}

func urlQueryEscape(value string) string {
	return strings.NewReplacer(" ", "%20", ":", "%3A", "-", "-").Replace(value)
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
