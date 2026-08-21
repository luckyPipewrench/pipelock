// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEvaluateGitPushAllowlistNilAndUnparseable(t *testing.T) {
	t.Parallel()

	cfg := config.GitProtection{Enabled: true, AllowedPushRepos: []string{"git.vendor.example/acme/private"}}
	if got := evaluateGitPushAllowlist(cfg, http.MethodPost, nil); got.Block {
		t.Fatalf("nil URL blocked: %+v", got)
	}

	emptyHost, err := url.Parse("https:///org/repo.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse empty host: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, http.MethodPost, emptyHost); got.Block {
		t.Fatalf("empty host treated as a push: %+v", got)
	}

	rootOnly, err := url.Parse("https://git.vendor.example/.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse empty-repo receive-pack: %v", err)
	}
	if repo, ok := gitPushRepoFromURL(rootOnly); ok || repo != "" {
		t.Fatalf("empty repo path parsed as %q", repo)
	}
}
