// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const gitReceivePackService = "git-receive-pack"

type gitPushDecision struct {
	Block  bool
	Repo   string
	Reason string
}

func evaluateGitPushAllowlist(cfg config.GitProtection, u *url.URL) gitPushDecision {
	if !cfg.Enabled || u == nil {
		return gitPushDecision{}
	}
	repo, ok := gitPushRepoFromURL(u)
	if !ok {
		return gitPushDecision{}
	}
	if len(cfg.AllowedPushRepos) == 0 {
		return gitPushDecision{
			Block:  true,
			Repo:   repo,
			Reason: "git push to non-allowlisted repo",
		}
	}
	if gitPushRepoAllowed(repo, cfg.AllowedPushRepos) {
		return gitPushDecision{}
	}
	return gitPushDecision{
		Block:  true,
		Repo:   repo,
		Reason: "git push to non-allowlisted repo",
	}
}

func gitPushRepoFromURL(u *url.URL) (string, bool) {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return "", false
	}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return "", false
	}
	var repoPath string
	switch {
	case strings.HasSuffix(path, "/"+gitReceivePackService):
		repoPath = strings.TrimSuffix(path, "/"+gitReceivePackService)
	case strings.HasSuffix(path, "/info/refs") && u.Query().Get("service") == gitReceivePackService:
		repoPath = strings.TrimSuffix(path, "/info/refs")
	default:
		return "", false
	}
	repoPath = strings.TrimSuffix(repoPath, ".git")
	repoPath = strings.Trim(repoPath, "/")
	if repoPath == "" {
		return "", false
	}
	return host + "/" + strings.ToLower(repoPath), true
}

func gitPushRepoAllowed(repo string, allowlist []string) bool {
	repo = strings.ToLower(strings.TrimSpace(repo))
	for _, raw := range allowlist {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		if gitPushRepoPatternMatch(pattern, repo) {
			return true
		}
	}
	return false
}

func gitPushRepoPatternMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	ok, err := filepath.Match(pattern, value)
	return err == nil && ok
}
