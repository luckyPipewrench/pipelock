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

func fakeGitLabPAT() string      { return "gl" + "pat-" + strings.Repeat("c", 20) }
func fakeGitLabJobToken() string { return "gl" + "cbt-" + strings.Repeat("d", 20) }

func gitAudienceHeaderConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	cfg.DLP.GitHubEnterpriseHosts = []string{"ghe.corp.example"}
	cfg.DLP.GitLabHosts = []string{"gitlab.corp.example"}
	return cfg
}

// Every header carrier the GitHub and GitLab audiences accept, and every one
// they refuse, through the real request-header scan including the joined
// cross-header pass.
func TestGitHubGitLabAudience_HeaderCarriers(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	gh, gl, job := fakeGitHubToken(), fakeGitLabPAT(), fakeGitLabJobToken()

	for _, tc := range []struct {
		name, header, value, target, pattern string
		clean                                bool
	}{
		{"github bearer api", "Authorization", "Bearer " + gh, "https://api.github.com/user", "GitHub Token", true},
		{"github token scheme uploads", "Authorization", "token " + gh, "https://uploads.github.com/repos/o/r/releases/1/assets", "GitHub Token", true},
		{"github declared ghes", "Authorization", "Bearer " + gh, "https://ghe.corp.example/api/v3/user", "GitHub Token", true},
		{"github other header", "X-Api-Key", gh, "https://api.github.com/user", "GitHub Token", false},
		{"github private-token header", "Private-Token", gh, "https://api.github.com/user", "GitHub Token", false},
		{"github web host", "Authorization", "Bearer " + gh, "https://github.com/login", "GitHub Token", false},
		{"github lookalike", "Authorization", "Bearer " + gh, "https://api.github.com.evil.example/user", "GitHub Token", false},
		{"github subdomain of declared", "Authorization", "Bearer " + gh, "https://x.ghe.corp.example/api/v3", "GitHub Token", false},
		{"github at declared gitlab host", "Authorization", "Bearer " + gh, "https://gitlab.corp.example/api/v4", "GitHub Token", false},
		{"github cleartext", "Authorization", "Bearer " + gh, "http://api.github.com/user", "GitHub Token", false},
		{"gitlab private-token", "Private-Token", gl, "https://gitlab.com/api/v4/user", "GitLab PAT", true},
		{"gitlab bearer", "Authorization", "Bearer " + gl, "https://gitlab.com/api/v4/user", "GitLab PAT", true},
		{"gitlab declared host", "Private-Token", gl, "https://gitlab.corp.example/api/v4/user", "GitLab PAT", true},
		{"gitlab undeclared self-managed", "Private-Token", gl, "https://gitlab.other.example/api/v4/user", "GitLab PAT", false},
		{"gitlab registry subdomain", "Authorization", "Bearer " + gl, "https://registry.gitlab.com/v2/", "GitLab PAT", false},
		{"gitlab pat on job-token header", "Job-Token", gl, "https://gitlab.com/api/v4/user", "GitLab PAT", false},
		{"gitlab pat at github", "Authorization", "Bearer " + gl, "https://api.github.com/user", "GitLab PAT", false},
		{"gitlab job token", "Job-Token", job, "https://gitlab.com/api/v4/job", "GitLab CI Job Token", true},
		{"gitlab job token declared", "Job-Token", job, "https://gitlab.corp.example/api/v4/job", "GitLab CI Job Token", true},
		{"gitlab job token on private-token", "Private-Token", job, "https://gitlab.com/api/v4/job", "GitLab CI Job Token", false},
		{"gitlab job token bearer", "Authorization", "Bearer " + job, "https://gitlab.com/api/v4/job", "GitLab CI Job Token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var allows []scanner.CredentialAudienceAllow
			result := scanRequestHeadersForTargetWithAudience(t.Context(), http.Header{tc.header: []string{tc.value}}, cfg, sc, tc.target, nil,
				func(a scanner.CredentialAudienceAllow) { allows = append(allows, a) })
			clean := result == nil || result.Clean
			if clean != tc.clean {
				t.Fatalf("clean=%t want %t result=%+v allows=%+v", clean, tc.clean, result, allows)
			}
			if tc.clean {
				if len(allows) != 1 || allows[0].PatternName != tc.pattern || allows[0].Surface != "header" {
					t.Fatalf("allows=%+v", allows)
				}
				return
			}
			found := false
			for _, m := range result.DLPMatches {
				found = found || m.PatternName == tc.pattern
			}
			if !found {
				t.Fatalf("block did not name %s: %+v", tc.pattern, result.DLPMatches)
			}
		})
	}
}

// An allowed GitHub token must not hide a different secret split across
// headers, and a GitHub token split across non-carrier headers stays blocked.
func TestGitHubAudience_JoinedHeadersKeepSplitSecrets(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	gh := fakeGitHubToken()
	target := "https://api.github.com/user"

	split := scanRequestHeadersForTarget(t.Context(), http.Header{
		"Authorization": []string{"Bearer " + gh + "AKIA" + strings.Repeat("A", 8)},
		"X-Split":       []string{"C" + strings.Repeat("A", 7)},
	}, cfg, sc, target)
	if split == nil || split.Clean {
		t.Fatal("AWS key split across Authorization and another header was hidden")
	}
	for _, m := range split.DLPMatches {
		if m.PatternName == "GitHub Token" {
			t.Fatalf("allowed GitHub token reblocked by joined scan: %+v", split.DLPMatches)
		}
	}

	// With no configured patterns only the immutable core copy matches. The
	// joined pass (header name plus value in all mode) must scrub the core
	// match too, or an allowed token is reblocked as "(joined)".
	coreOnly := gitAudienceHeaderConfig()
	coreOnly.DLP.Patterns = nil
	coreSC := scanner.MustNew(coreOnly)
	t.Cleanup(coreSC.Close)
	var coreAllows []scanner.CredentialAudienceAllow
	coreResult := scanRequestHeadersForTargetWithAudience(t.Context(), http.Header{"Authorization": []string{"Bearer " + gh}}, coreOnly, coreSC, target, nil,
		func(a scanner.CredentialAudienceAllow) { coreAllows = append(coreAllows, a) })
	if coreResult != nil && !coreResult.Clean {
		t.Fatalf("core-only GitHub token reblocked by joined scan: %+v", coreResult.DLPMatches)
	}
	if len(coreAllows) == 0 {
		t.Fatal("core-only GitHub token earned no audience allow")
	}

	splitGH := scanRequestHeadersForTarget(t.Context(), http.Header{
		"Authorization": []string{"Bearer " + gh},
		"X-First":       []string{"gh" + "p_"},
		"X-Second":      []string{strings.Repeat("z", 36)},
	}, cfg, sc, target)
	if splitGH == nil || splitGH.Clean {
		t.Fatal("GitHub token split across non-Authorization headers was allowed")
	}
}

func TestGitHubGitLabAudience_BodyAndWebSocketStayBlocked(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct{ token, target string }{
		{fakeGitHubToken(), "https://api.github.com/user"},
		{fakeGitLabPAT(), "https://gitlab.com/api/v4/user"},
		{fakeGitLabJobToken(), "https://gitlab.com/api/v4/job"},
	} {
		_, body := scanRequestBody(context.Background(), BodyScanRequest{
			Body: strings.NewReader(`{"credential":"` + tc.token + `"}`), ContentType: "application/json",
			MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: tc.target, AudienceSurface: "body",
		})
		if body.Clean {
			t.Fatalf("%s in request body allowed at %s", tc.token[:6], tc.target)
		}
		relay := newCredentialAudienceWebSocketRelay(sc, cfg, strings.Replace(tc.target, "https://", "wss://", 1))
		if !relay.scanClientText(t.Context(), audit.NewNop(), []byte(tc.token)) {
			t.Fatalf("%s in WebSocket frame allowed", tc.token[:6])
		}
	}

	gh := fakeGitHubToken()
	for _, tc := range []struct {
		name, header, value string
		block               bool
	}{
		{"Authorization", "Authorization", "Bearer " + gh, false},
		{"other header", "X-Api-Key", gh, true},
	} {
		t.Run("WebSocket upgrade "+tc.name, func(t *testing.T) {
			p := &Proxy{metrics: metrics.New(), logger: audit.NewNop()}
			blocked, _, _, _ := p.dlpScanWSHeaders(t.Context(), http.Header{tc.header: []string{tc.value}}, sc, cfg, "wss://api.github.com/graphql", audit.LogContext{})
			if blocked != tc.block {
				t.Fatalf("blocked=%t want %t", blocked, tc.block)
			}
		})
	}
}

// With no declared hosts the enterprise instance receives nothing: the
// declared list is the only way to reach a GHES or self-managed host.
func TestGitHubGitLabAudience_UndeclaredEnterpriseBlocked(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	cfg.DLP.GitHubEnterpriseHosts = nil
	cfg.DLP.GitLabHosts = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct{ header, value, target string }{
		{"Authorization", "Bearer " + fakeGitHubToken(), "https://ghe.corp.example/api/v3/user"},
		{"Private-Token", fakeGitLabPAT(), "https://gitlab.corp.example/api/v4/user"},
	} {
		r := scanRequestHeadersForTarget(t.Context(), http.Header{tc.header: []string{tc.value}}, cfg, sc, tc.target)
		if r == nil || r.Clean {
			t.Fatalf("undeclared enterprise host %s allowed", tc.target)
		}
	}
}
