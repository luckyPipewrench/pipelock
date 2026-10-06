// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	azureSASOverrideBase = `version: 1
mode: balanced
dlp:
  patterns:
    - name: Azure SAS Token
      regex: '\bsig=(?:[A-Za-z0-9%]{43,}%3d\b|[A-Za-z0-9+/]{43}=)'
      severity: high
      exempt_domains:
`
	otherSASHost = "downloads.vendor.example"
)

func scannerFromOverride(t *testing.T, exempt ...string) *Scanner {
	t.Helper()
	var b strings.Builder
	b.WriteString(azureSASOverrideBase)
	for _, host := range exempt {
		b.WriteString("        - " + host + "\n")
	}
	cfg, err := config.LoadBytes([]byte(b.String()))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	cfg.Internal = nil
	s := MustNew(cfg)
	s.now = func() time.Time { return time.Unix(1100, 0) }
	t.Cleanup(s.Close)
	return s
}

// A same-name Azure SAS pattern whose only change is an exemption keeps the
// release-grant audience: the release redirect still passes, the exempt host
// is skipped, and every other host still blocks.
func TestScan_SameNameAzureSASWithExemptionKeepsReleaseGrantAudience(t *testing.T) {
	t.Parallel()
	s := scannerFromOverride(t, otherSASHost)
	jwt := fakeAudienceJWT()
	// A low-entropy signature of the real shape keeps the query-entropy check out
	// of this test: exempt_domains is a DLP control, and entropy is judged
	// separately.
	sasOnly := "sp=r&sig=" + strings.Repeat("A", 43) + "="

	release := "https://" + githubReleaseAssetsHost + "/github-production-release-asset/1/asset?" + releaseGrantSASQuery(jwt, "exempt-release-fixture")
	if r := s.Scan(context.Background(), release); !r.Allowed {
		t.Fatalf("release redirect blocked after an exempt-only override: scanner=%s reason=%s", r.Scanner, r.Reason)
	}
	if r := s.Scan(context.Background(), "https://"+otherSASHost+"/blob?"+sasOnly); !r.Allowed {
		t.Fatalf("exempt host blocked: scanner=%s reason=%s", r.Scanner, r.Reason)
	}
	for _, target := range []string{
		"https://other.vendor.example/blob?" + sasOnly,
		"https://" + otherSASHost + ".evil.example/blob?" + sasOnly,
	} {
		if r := s.Scan(context.Background(), target); r.Allowed {
			t.Fatalf("SAS allowed at a host the operator did not exempt: %s", target)
		}
	}
}

// An exempt entry the audience already covers is ignored: the release host
// keeps its carrier rules, so a SAS there without the grant still blocks.
func TestScan_ExemptionInsideAudienceIsIgnored(t *testing.T) {
	t.Parallel()
	s := scannerFromOverride(t, githubReleaseAssetsHost)
	sasOnly := "sp=r&sig=" + url.QueryEscape(releaseGrantSASSig("inside-fixture"))
	if r := s.Scan(context.Background(), "https://"+githubReleaseAssetsHost+"/github-production-release-asset/1/asset?"+sasOnly); r.Allowed {
		t.Fatal("an exemption for the audience host opened a SAS with no release grant")
	}
	jwt := fakeAudienceJWT()
	release := "https://" + githubReleaseAssetsHost + "/github-production-release-asset/1/asset?" + releaseGrantSASQuery(jwt, "inside-release-fixture")
	if r := s.Scan(context.Background(), release); !r.Allowed {
		t.Fatalf("real release redirect blocked: scanner=%s reason=%s", r.Scanner, r.Reason)
	}
}

// A same-name pattern that changes what it matches is a separate pattern with
// no audience: the release redirect blocks, which is the outcome the load-time
// warning exists to explain.
func TestScan_SameNameAzureSASWithChangedRegexLosesAudience(t *testing.T) {
	t.Parallel()
	yaml := strings.Replace(azureSASOverrideBase, "severity: high", "severity: medium", 1) + "        - " + otherSASHost + "\n"
	cfg, err := config.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	cfg.Internal = nil
	s := MustNew(cfg)
	s.now = func() time.Time { return time.Unix(1100, 0) }
	defer s.Close()
	release := "https://" + githubReleaseAssetsHost + "/github-production-release-asset/1/asset?" + releaseGrantSASQuery(fakeAudienceJWT(), "changed-fixture")
	if r := s.Scan(context.Background(), release); r.Allowed {
		t.Fatal("a customized same-name pattern kept the built-in release-grant audience")
	}
}
