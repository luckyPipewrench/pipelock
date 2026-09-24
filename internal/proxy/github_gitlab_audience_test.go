// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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
		// Git over HTTPS sends HTTP Basic. The git rule accepts it only at the
		// git host and only on a git smart-HTTP or LFS path; the REST hosts
		// never accept Basic. GitLab git uses Basic oauth2:<token>.
		{"github basic x-access-token at github.com", "Authorization", basicAuth("x-access-token", gh), "https://github.com/o/r.git/git-upload-pack", "GitHub Token", true},
		{"github basic user info/refs no service", "Authorization", basicAuth("octocat", gh), "https://github.com/o/r.git/info/refs", "GitHub Token", false},
		{"github basic at api", "Authorization", basicAuth("x-access-token", gh), "https://api.github.com/user", "GitHub Token", false},
		{"github unknown scheme at api", "Authorization", "Digest " + gh, "https://api.github.com/user", "GitHub Token", false},
		{"gitlab basic oauth2", "Authorization", basicAuth("oauth2", gl), "https://gitlab.com/g/r.git/git-receive-pack", "GitLab PAT", true},
		{"gitlab basic declared host", "Authorization", basicAuth("oauth2", gl), "https://gitlab.corp.example/g/r.git/info/refs?service=git-upload-pack", "GitLab PAT", true},
		{"gitlab basic lookalike", "Authorization", basicAuth("oauth2", gl), "https://gitlab.com.evil.example/g/r.git/info/refs", "GitLab PAT", false},
		{"gitlab token scheme", "Authorization", "token " + gl, "https://gitlab.com/api/v4/user", "GitLab PAT", false},
		{"gitlab job token basic", "Authorization", basicAuth("gitlab-ci-token", job), "https://gitlab.com/g/r.git/info/refs", "GitLab CI Job Token", false},
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
			if len(allows) != 0 {
				t.Fatalf("blocked request recorded audience allows: %+v", allows)
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

func assertNoCredentialAudienceWebSocketMetric(t *testing.T, m *metrics.Metrics) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if strings.Contains(rec.Body.String(), "pipelock_dlp_credential_audience_allows_total{") {
		t.Fatalf("blocked WebSocket handshake recorded an audience allow: %s", rec.Body.String())
	}
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// An audience allow records that a credential was delivered, so it must never
// be emitted for a request the same scan blocks. Each case pairs a credential
// its audience accepts with, in some cases, a second header that blocks.
func TestCredentialAudience_AllowImpliesClean(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	gh, gl, job := fakeGitHubToken(), fakeGitLabPAT(), fakeGitLabJobToken()
	slack := fakeSlackBotToken()
	google := "ya29." + strings.Repeat("a", 24)
	aws := "AKIA" + strings.Repeat("B", 16)

	type headerCase struct {
		name    string
		headers http.Header
		target  string
		clean   bool
	}
	cases := []headerCase{
		{"gitlab basic", http.Header{"Authorization": {basicAuth("oauth2", gl)}}, "https://gitlab.com/g/r.git/git-receive-pack", true},
		{"gitlab basic plus host header", http.Header{"Authorization": {basicAuth("oauth2", gl)}, "User-Agent": {"git/2.45"}}, "https://gitlab.com/g/r.git/info/refs?service=git-upload-pack", true},
		{"gitlab basic plus aws", http.Header{"Authorization": {basicAuth("oauth2", gl)}, "X-Extra": {aws}}, "https://gitlab.com/g/r.git/info/refs?service=git-upload-pack", false},
		{"github git basic plus aws", http.Header{"Authorization": {basicAuth("x-access-token", gh)}, "X-Extra": {aws}}, "https://github.com/o/r.git/git-upload-pack", false},
		{"github git basic plus agent header", http.Header{"Authorization": {basicAuth("x-access-token", gh)}, "User-Agent": {"git/2.45"}}, "https://github.com/o/r.git/git-upload-pack", true},
		{"gitlab bearer plus aws", http.Header{"Authorization": {"Bearer " + gl}, "X-Extra": {aws}}, "https://gitlab.com/api/v4/user", false},
		{"gitlab private-token plus job on bearer", http.Header{"Private-Token": {gl}, "Authorization": {"Bearer " + job}}, "https://gitlab.com/api/v4/user", false},
		{"github bearer plus github in other header", http.Header{"Authorization": {"Bearer " + gh}, "X-Api-Key": {gh}}, "https://api.github.com/user", false},
		{"github basic at github.com non-git path", http.Header{"Authorization": {basicAuth("x-access-token", gh)}}, "https://github.com/o/r", false},
		{"slack basic", http.Header{"Authorization": {basicAuth("u", slack)}}, "https://slack.com/api/auth.test", true},
		{"slack bearer base64", http.Header{"Authorization": {"Bearer " + base64.StdEncoding.EncodeToString([]byte(slack))}}, "https://slack.com/api/auth.test", true},
		{"slack bearer plus aws", http.Header{"Authorization": {"Bearer " + slack}, "X-Extra": {aws}}, "https://slack.com/api/auth.test", false},
		{"google bearer plus aws", http.Header{"Authorization": {"Bearer " + google}, "X-Extra": {aws}}, "https://gmail.googleapis.com/gmail/v1/users/me/profile", false},
		{"google basic", http.Header{"Authorization": {basicAuth("u", google)}}, "https://gmail.googleapis.com/gmail/v1/users/me/profile", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var allows []scanner.CredentialAudienceAllow
			result := scanRequestHeadersForTargetWithAudience(t.Context(), tc.headers, cfg, sc, tc.target, nil,
				func(a scanner.CredentialAudienceAllow) { allows = append(allows, a) })
			clean := result == nil || result.Clean
			if clean != tc.clean {
				t.Fatalf("clean=%t want %t result=%+v allows=%+v", clean, tc.clean, result, allows)
			}
			if len(allows) > 0 && !clean {
				t.Fatalf("audience allow emitted for a blocked request: allows=%+v result=%+v", allows, result)
			}
			if clean && len(allows) != 1 {
				t.Fatalf("clean audience request emitted %d allows: %+v", len(allows), allows)
			}
		})
	}

	// The body path follows the same invariant: an allowed credential beside
	// an unrelated secret produces a block and no allow.
	var bodyAllows []scanner.CredentialAudienceAllow
	_, body := scanRequestBody(context.Background(), BodyScanRequest{
		Body: strings.NewReader(`{"a":"` + slack + `","b":"` + aws + `"}`), ContentType: "application/json",
		MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: "https://slack.com/api/auth.test", AudienceSurface: "body",
		OnCredentialAudienceAllow: func(a scanner.CredentialAudienceAllow) { bodyAllows = append(bodyAllows, a) },
	})
	if body.Clean || len(bodyAllows) != 0 {
		t.Fatalf("body with allowed and unrelated secret: clean=%t allows=%+v", body.Clean, bodyAllows)
	}

	// WebSocket upgrade headers: a blocked handshake records no allow metric.
	p := &Proxy{metrics: metrics.New(), logger: audit.NewNop()}
	blocked, _, _, _ := p.dlpScanWSHeaders(t.Context(), http.Header{"Authorization": {"Bearer " + gh}, "X-Api-Key": {gh}}, sc, cfg, "wss://api.github.com/graphql", audit.LogContext{})
	if !blocked {
		t.Fatal("WebSocket upgrade with GitHub token in X-Api-Key allowed")
	}
	assertNoCredentialAudienceWebSocketMetric(t, p.metrics)
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

// The git-over-HTTPS rule: Basic, https, a git host, and a git smart-HTTP or
// LFS path, all four at once. Each blocked case drops exactly one of them.
func TestGitHubGitLabAudience_GitTransportRule(t *testing.T) {
	cfg := gitAudienceHeaderConfig()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	gh := fakeGitHubToken()
	pat := "github" + "_pat_" + strings.Repeat("A", 40)
	gl := fakeGitLabPAT()

	for _, tc := range []struct {
		name, value, target, pattern string
		clean                        bool
	}{
		{"x-access-token receive-pack discovery", basicAuth("x-access-token", gh), "https://github.com/o/r.git/info/refs?service=git-receive-pack", "GitHub Token", true},
		{"user upload-pack discovery", basicAuth("octocat", gh), "https://github.com/o/r/info/refs?service=git-upload-pack", "GitHub Token", true},
		{"upload-pack no .git", basicAuth("x-access-token", gh), "https://github.com/o/r/git-upload-pack", "GitHub Token", true},
		{"receive-pack", basicAuth("octocat", gh), "https://github.com/o/r.git/git-receive-pack", "GitHub Token", true},
		{"lfs batch", basicAuth("x-access-token", gh), "https://github.com/o/r.git/info/lfs/objects/batch", "GitHub Token", true},
		{"lfs locks", basicAuth("octocat", gh), "https://github.com/o/r.git/info/lfs/locks/verify", "GitHub Token", true},
		{"fine-grained pat", basicAuth("x-access-token", pat), "https://github.com/o/r.git/git-upload-pack", "GitHub Fine-Grained PAT", true},
		{"declared ghes git path", basicAuth("x-access-token", gh), "https://ghe.corp.example/o/r.git/info/refs?service=git-upload-pack", "GitHub Token", true},
		{"settings page", basicAuth("x-access-token", gh), "https://github.com/settings/tokens", "GitHub Token", false},
		{"repo page", basicAuth("x-access-token", gh), "https://github.com/o/r", "GitHub Token", false},
		{"info/refs without service", basicAuth("x-access-token", gh), "https://github.com/o/r/info/refs", "GitHub Token", false},
		{"info/refs unknown service", basicAuth("x-access-token", gh), "https://github.com/o/r/info/refs?service=git-evil", "GitHub Token", false},
		{"info/refs extra query", basicAuth("x-access-token", gh), "https://github.com/o/r/info/refs?service=git-upload-pack&x=1", "GitHub Token", false},
		{"bare service path", basicAuth("x-access-token", gh), "https://github.com/git-upload-pack", "GitHub Token", false},
		{"bearer at git path", "Bearer " + gh, "https://github.com/o/r.git/git-upload-pack", "GitHub Token", false},
		{"token scheme at git path", "token " + gh, "https://github.com/o/r.git/git-upload-pack", "GitHub Token", false},
		{"basic at api git path", basicAuth("x-access-token", gh), "https://api.github.com/o/r.git/git-upload-pack", "GitHub Token", false},
		{"lookalike host", basicAuth("x-access-token", gh), "https://github.com.evil.example/o/r.git/git-upload-pack", "GitHub Token", false},
		{"subdomain of github.com", basicAuth("x-access-token", gh), "https://gist.github.com/o/r.git/git-upload-pack", "GitHub Token", false},
		{"cleartext", basicAuth("x-access-token", gh), "http://github.com/o/r.git/git-upload-pack", "GitHub Token", false},
		{"traversal out of git path", basicAuth("x-access-token", gh), "https://github.com/o/r.git/git-upload-pack/../../settings/tokens", "GitHub Token", false},
		{"traversal into git path", basicAuth("x-access-token", gh), "https://github.com/settings/../o/r/git-upload-pack", "GitHub Token", false},
		{"encoded slash", basicAuth("x-access-token", gh), "https://github.com/settings%2Ftokens/git-upload-pack", "GitHub Token", false},
		{"double slash", basicAuth("x-access-token", gh), "https://github.com//git-upload-pack", "GitHub Token", false},
		{"github token at gitlab git path", basicAuth("x-access-token", gh), "https://gitlab.com/g/r.git/git-upload-pack", "GitHub Token", false},
		{"gitlab basic git path", basicAuth("oauth2", gl), "https://gitlab.com/g/r.git/info/refs?service=git-receive-pack", "GitLab PAT", true},
		{"gitlab basic lfs", basicAuth("oauth2", gl), "https://gitlab.com/g/r.git/info/lfs/objects/batch", "GitLab PAT", true},
		{"gitlab basic non-git path", basicAuth("oauth2", gl), "https://gitlab.com/api/v4/user", "GitLab PAT", false},
		{"gitlab bearer rest unchanged", "Bearer " + gl, "https://gitlab.com/api/v4/projects", "GitLab PAT", true},
		{"gitlab token at github git path", basicAuth("oauth2", gl), "https://github.com/o/r.git/git-upload-pack", "GitLab PAT", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var allows []scanner.CredentialAudienceAllow
			result := scanRequestHeadersForTargetWithAudience(t.Context(), http.Header{"Authorization": []string{tc.value}}, cfg, sc, tc.target, nil,
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
			if len(allows) != 0 {
				t.Fatalf("blocked request recorded audience allows: %+v", allows)
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

	// The git rule never applies to a WebSocket upgrade, even at a git path.
	p := &Proxy{metrics: metrics.New(), logger: audit.NewNop()}
	blocked, _, _, _ := p.dlpScanWSHeaders(t.Context(), http.Header{"Authorization": {basicAuth("x-access-token", gh)}}, sc, cfg, "wss://github.com/o/r.git/git-upload-pack", audit.LogContext{})
	if !blocked {
		t.Fatal("WebSocket upgrade with GitHub Basic at a git path allowed")
	}
}
