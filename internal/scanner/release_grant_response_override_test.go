// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	// realReleaseAssetName is the asset name a live GitHub release redirect
	// carried in rscd and response-content-disposition on 2026-10-06. On its
	// own it scores 4.63 against the 4.50 default entropy threshold.
	realReleaseAssetName    = "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz.sha256"
	releaseOverrideDispoFmt = "attachment; filename="
)

// releaseOverrideTarget builds a release redirect whose two content-disposition
// overrides carry disposition, with every other parameter as GitHub sends it.
func releaseOverrideTarget(disposition string) string {
	query := releaseGrantSASQuery(fakeAudienceJWT(), "override-fixture")
	query = strings.Replace(query, "rscd=attachment%3B+filename%3Dtool_1.0_checksums.txt", "rscd="+url.QueryEscape(disposition), 1)
	query = strings.Replace(query, "response-content-disposition=attachment%3B%20filename%3Dtool_1.0_checksums.txt", "response-content-disposition="+url.PathEscape(disposition), 1)
	return "https://" + githubReleaseAssetsHost + "/github-production-release-asset/53631945/00000000-0000-4000-8000-000000000003?" + query
}

// highEntropyName returns n bytes of a letters-and-digits name with high
// Shannon entropy, derived from fixed seeds so no secret-shaped literal sits in
// source.
func highEntropyName(n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(strings.NewReplacer("+", "Q", "/", "z", "=", "").Replace(releaseGrantSASSig("name-" + strconv.Itoa(i))))
	}
	return b.String()[:n]
}

func newReleaseOverrideScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	s.now = func() time.Time { return time.Unix(1100, 0) }
	t.Cleanup(s.Close)
	return s
}

// A real release asset with a long name must pass the default entropy check
// on the grant path. Before the override shape was pinned, rscd alone scored
// 4.63 and blocked the redirect.
func TestScan_GitHubReleaseGrant_LongAssetNameClearsEntropy(t *testing.T) {
	t.Parallel()
	s := newReleaseOverrideScanner(t)
	for _, name := range []string{
		realReleaseAssetName,
		"bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz",
		highEntropyName(255), // the longest name the pin accepts
	} {
		target := releaseOverrideTarget(releaseOverrideDispoFmt + name)
		if got := ShannonEntropy(name); got <= s.entropyThreshold && name == realReleaseAssetName {
			t.Fatalf("fixture name no longer exceeds the entropy threshold: %.2f", got)
		}
		result := s.Scan(context.Background(), target)
		if !result.Allowed {
			t.Errorf("%q blocked: scanner=%s reason=%s", name, result.Scanner, result.Reason)
		}
	}
}

// The exemption is a shape pin on a valid grant, never a key exemption. Each
// case keeps the URL blocked.
func TestScan_GitHubReleaseGrant_ResponseOverrideStaysPinned(t *testing.T) {
	t.Parallel()
	s := newReleaseOverrideScanner(t)
	good := releaseOverrideDispoFmt + realReleaseAssetName
	grant := releaseOverrideTarget(good)
	jwtParam := "&jwt=" + fakeAudienceJWT()

	for _, tc := range []struct {
		name   string
		target string
	}{
		{"name over 255 bytes", releaseOverrideTarget(releaseOverrideDispoFmt + highEntropyName(256))},
		{"name with a path separator", releaseOverrideTarget(releaseOverrideDispoFmt + "dir/" + realReleaseAssetName)},
		{"name with a space", releaseOverrideTarget(releaseOverrideDispoFmt + "ripgrep 14.1.1-" + highEntropyName(60))},
		{"name with a percent escape", releaseOverrideTarget(releaseOverrideDispoFmt + "ripgrep%41-x86_64-unknown-linux-musl.tar.gz.sha256")},
		{"extra disposition parameter", releaseOverrideTarget(good + "; filename*=UTF-8''" + realReleaseAssetName)},
		{"inline disposition", releaseOverrideTarget("inline; filename=" + realReleaseAssetName)},
		{"free text value", releaseOverrideTarget("Zk3pQ9xV7mL2wT8nB5cR1yH6jD4sF0aGeU")},
		{"case alias of the key", strings.Replace(grant, "rscd=", "RSCD=", 1)},
		{"repeated key", grant + "&rscd=" + url.QueryEscape(good)},
		{"high entropy value under another key", grant + "&x=" + url.QueryEscape("Zk3pQ9xV7mL2wT8nB5cR1yH6jD4sF0aGeU")},
		{"bad content type", strings.Replace(grant, "response-content-type=application%2Foctet-stream", "response-content-type="+url.QueryEscape("Zk3pQ9xV7mL2wT8nB5cR1yH6jD4sF0aGeU/Aa1Bb2"), 1)},
		{"grant jwt missing", strings.Replace(grant, jwtParam, "", 1)},
		{"non-grant host", strings.Replace(grant, githubReleaseAssetsHost, "api.vendor.example", 1)},
		{"plain http", strings.Replace(grant, "https://", "http://", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := s.Scan(context.Background(), tc.target)
			if result.Allowed {
				t.Fatal("allowed, want blocked")
			}
			if strings.HasPrefix(tc.name, "name ") || strings.HasSuffix(tc.name, "value") || strings.HasPrefix(tc.name, "extra ") {
				if result.Scanner != ScannerEntropy {
					t.Fatalf("blocked by %s (%s), want the entropy check the pin failed to exempt", result.Scanner, result.Reason)
				}
			}
		})
	}

	if result := s.Scan(context.Background(), grant); !result.Allowed {
		t.Fatalf("control grant blocked: scanner=%s reason=%s", result.Scanner, result.Reason)
	}
}

// A grant whose window has lapsed no longer carries the exemption.
func TestScan_GitHubReleaseGrant_ResponseOverrideNeedsLiveGrant(t *testing.T) {
	t.Parallel()
	s := newReleaseOverrideScanner(t)
	s.now = func() time.Time { return time.Unix(1_000_000, 0) }
	if result := s.Scan(context.Background(), releaseOverrideTarget(releaseOverrideDispoFmt+realReleaseAssetName)); result.Allowed {
		t.Fatal("expired grant kept the response-override exemption")
	}
}

// The pin lets a name through entropy only; DLP still reads it. A credential
// planted in the filename keeps the URL blocked.
func TestScan_GitHubReleaseGrant_ResponseOverrideStillScannedByDLP(t *testing.T) {
	t.Parallel()
	s := newReleaseOverrideScanner(t)
	secret := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	result := s.Scan(context.Background(), releaseOverrideTarget(releaseOverrideDispoFmt+"tool-"+secret+".tar.gz"))
	if result.Allowed {
		t.Fatal("credential in an override filename was allowed")
	}
}
