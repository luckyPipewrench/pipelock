// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestCredentialAudienceHeaderSurface pins every carrier the header surface
// classifier distinguishes. A scheme word decides the surface; any
// Authorization value that is not exactly "<scheme> <credential>" is a surface
// no audience accepts.
func TestCredentialAudienceHeaderSurface(t *testing.T) {
	for _, tc := range []struct {
		header, value, want string
	}{
		{"Authorization", "Bearer abc", CredentialAudienceAuthorizationHeaderSurface},
		{"authorization", "bearer abc", CredentialAudienceAuthorizationHeaderSurface},
		{"Authorization", "token abc", credentialAudienceAuthorizationTokenSurface},
		{"Authorization", "Basic abc", credentialAudienceAuthorizationBasicSurface},
		{"Authorization", "Digest abc", credentialAudienceAuthorizationOtherSurface},
		{"Authorization", "Bearer abc extra", credentialAudienceAuthorizationOtherSurface},
		{"Authorization", "abc", credentialAudienceAuthorizationOtherSurface},
		{"PRIVATE-TOKEN", "abc", credentialAudiencePrivateTokenSurface},
		{"Job-Token", "abc", credentialAudienceJobTokenSurface},
		{"X-Api-Key", "abc", "header"},
	} {
		if got := CredentialAudienceHeaderSurface(tc.header, tc.value); got != tc.want {
			t.Errorf("CredentialAudienceHeaderSurface(%q, %q) = %q, want %q", tc.header, tc.value, got, tc.want)
		}
	}
}

// TestGitTransportAllowedEdges covers the git rule's refusals that do not
// depend on a proxy path: the wrong surface or carrier bit, a host outside the
// git host set, an unparseable or non-https target, and paths or queries that
// only resemble a git endpoint. The positive rows are the controls that prove
// each refusal is caused by the mutated field.
func TestGitTransportAllowedEdges(t *testing.T) {
	git := credentialAudienceCandidate{
		patternName: "GitHub Token",
		carrierMask: config.CredentialAudienceCarrierGitBasic,
		gitHosts:    []string{"github.com"},
	}
	noBit := git
	noBit.carrierMask = config.CredentialAudienceCarrierAuthorizationBearer
	noHosts := git
	noHosts.gitHosts = nil
	basic := credentialAudienceAuthorizationBasicSurface
	for _, tc := range []struct {
		name      string
		candidate credentialAudienceCandidate
		host      string
		target    string
		surface   string
		want      bool
	}{
		{"upload-pack", git, "github.com", "https://github.com/o/r.git/git-upload-pack", basic, true},
		{"receive-pack without .git", git, "github.com", "https://github.com/o/r/git-receive-pack", basic, true},
		{"info/refs upload-pack", git, "github.com", "https://github.com/o/r.git/info/refs?service=git-upload-pack", basic, true},
		{"lfs batch", git, "github.com", "https://github.com/o/r.git/info/lfs/objects/batch", basic, true},
		{"bearer surface", git, "github.com", "https://github.com/o/r.git/git-upload-pack", CredentialAudienceAuthorizationHeaderSurface, false},
		{"no git carrier bit", noBit, "github.com", "https://github.com/o/r.git/git-upload-pack", basic, false},
		{"no git hosts", noHosts, "github.com", "https://github.com/o/r.git/git-upload-pack", basic, false},
		{"other host", git, "gitlab.com", "https://gitlab.com/o/r.git/git-upload-pack", basic, false},
		{"unparseable target", git, "github.com", "https://github.com/o/r\x7f.git/git-upload-pack", basic, false},
		{"cleartext", git, "github.com", "http://github.com/o/r.git/git-upload-pack", basic, false},
		{"websocket scheme", git, "github.com", "wss://github.com/o/r.git/git-upload-pack", basic, false},
		{"empty path", git, "github.com", "https://github.com", basic, false},
		{"percent-encoded path", git, "github.com", "https://github.com/o/r%2Fx/git-upload-pack", basic, false},
		{"traversal path", git, "github.com", "https://github.com/settings/../o/r/git-upload-pack", basic, false},
		{"trailing slash", git, "github.com", "https://github.com/o/r/git-upload-pack/", basic, false},
		{"lfs without repo", git, "github.com", "https://github.com/info/lfs/objects/batch", basic, false},
		{"lfs without suffix", git, "github.com", "https://github.com/o/r/info/lfs/", basic, false},
		{"service without repo", git, "github.com", "https://github.com/git-upload-pack", basic, false},
		{"info/refs without service", git, "github.com", "https://github.com/o/r/info/refs", basic, false},
		{"info/refs without repo", git, "github.com", "https://github.com/info/refs?service=git-upload-pack", basic, false},
		{"info/refs extra query", git, "github.com", "https://github.com/o/r/info/refs?service=git-upload-pack&x=1", basic, false},
		{"info/refs repeated service", git, "github.com", "https://github.com/o/r/info/refs?service=git-upload-pack&service=git-upload-pack", basic, false},
		{"info/refs unknown service", git, "github.com", "https://github.com/o/r/info/refs?service=git-upload-archive", basic, false},
		{"info/refs malformed query", git, "github.com", "https://github.com/o/r/info/refs?service=%zz", basic, false},
		{"settings page", git, "github.com", "https://github.com/settings/tokens", basic, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gitTransportAllowed(tc.candidate, tc.host, tc.target, tc.surface); got != tc.want {
				t.Fatalf("gitTransportAllowed(%q) = %t, want %t", tc.target, got, tc.want)
			}
		})
	}
}
