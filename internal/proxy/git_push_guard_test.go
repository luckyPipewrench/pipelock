// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestGitPushRepoFromURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{
			name: "post receive pack",
			raw:  "https://github.com/Acme/Project.git/git-receive-pack",
			want: "github.com/acme/project",
			ok:   true,
		},
		{
			name: "info refs receive pack",
			raw:  "https://github.com/acme/project.git/info/refs?service=git-receive-pack",
			want: "github.com/acme/project",
			ok:   true,
		},
		{
			name: "upload pack is not push",
			raw:  "https://github.com/acme/project.git/info/refs?service=git-upload-pack",
			ok:   false,
		},
		{
			name: "ordinary repo path",
			raw:  "https://github.com/acme/project",
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			got, ok := gitPushRepoFromURL(u)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("gitPushRepoFromURL() = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEvaluateGitPushAllowlist(t *testing.T) {
	cfg := config.GitProtection{
		Enabled:          true,
		AllowedPushRepos: []string{"github.com/acme/private", "gitlab.com/group/*", "example.com/*"},
	}
	blockedURL, err := url.Parse("https://github.com/acme/public.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse blocked URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, blockedURL); !got.Block {
		t.Fatalf("expected non-allowlisted push to block, got %+v", got)
	}
	allowedURL, err := url.Parse("https://github.com/acme/private.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse allowed URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, allowedURL); got.Block {
		t.Fatalf("expected allowlisted push to pass, got %+v", got)
	}
	hostWideURL, err := url.Parse("https://example.com/acme/project.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse host-wide URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, hostWideURL); got.Block {
		t.Fatalf("expected host-wide allowlisted push to pass, got %+v", got)
	}
	nestedGroupURL, err := url.Parse("https://gitlab.com/group/subgroup/project.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse nested group URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, nestedGroupURL); !got.Block {
		t.Fatalf("owner-level allowlist must not match nested group path, got %+v", got)
	}
	// host/* must match on a path-segment boundary, never a host-prefix
	// substring: example.com/* must not allow a look-alike host that merely
	// starts with the allowed host string (example.com.attacker.test).
	lookalikeHostURL, err := url.Parse("https://example.com.attacker.test/acme/project.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse look-alike host URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, lookalikeHostURL); !got.Block {
		t.Fatalf("host/* must not match a look-alike host prefix, got %+v", got)
	}
	disabled := cfg
	disabled.Enabled = false
	if got := evaluateGitPushAllowlist(disabled, blockedURL); got.Block {
		t.Fatalf("disabled git protection blocked: %+v", got)
	}
}

func TestEvaluateGitPushAllowlistBlocksEmptyAllowlist(t *testing.T) {
	cfg := config.GitProtection{Enabled: true}
	u, err := url.Parse("https://github.com/acme/public.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, u); !got.Block {
		t.Fatalf("enabled git push protection with empty allowlist must block, got %+v", got)
	}
}

func TestEvaluateGitPushAllowlistDoesNotMatchHostlessRepoPath(t *testing.T) {
	cfg := config.GitProtection{
		Enabled:          true,
		AllowedPushRepos: []string{"acme/private"},
	}
	u, err := url.Parse("https://evil.example/acme/private.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, u); !got.Block {
		t.Fatalf("hostless allowlist entry must not allow arbitrary host path, got %+v", got)
	}
}
