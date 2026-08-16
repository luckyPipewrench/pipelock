// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestEvaluateGitPushAllowlistNilAndUnparseable(t *testing.T) {
	t.Parallel()

	cfg := config.GitProtection{Enabled: true, AllowedPushRepos: []string{"github.com/acme/private"}}
	if got := evaluateGitPushAllowlist(cfg, nil); got.Block {
		t.Fatalf("nil URL blocked: %+v", got)
	}

	emptyHost, err := url.Parse("https:///org/repo.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse empty host: %v", err)
	}
	if got := evaluateGitPushAllowlist(cfg, emptyHost); got.Block {
		t.Fatalf("empty host treated as a push: %+v", got)
	}

	rootOnly, err := url.Parse("https://github.com/.git/git-receive-pack")
	if err != nil {
		t.Fatalf("parse empty-repo receive-pack: %v", err)
	}
	if repo, ok := gitPushRepoFromURL(rootOnly); ok || repo != "" {
		t.Fatalf("empty repo path parsed as %q", repo)
	}
}
