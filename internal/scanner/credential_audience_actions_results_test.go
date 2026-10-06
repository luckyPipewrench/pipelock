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
	actionsResultsHost = "productionresultssa1.blob.core.windows.net"
	actionsResultsRun  = "/actions-results/00000000-0000-4000-8000-000000000011/workflow-job-run-00000000-0000-4000-8000-000000000012"
)

func actionsResultsLogURL(host, query string) string {
	return "https://" + host + actionsResultsRun + "/logs/job/job-logs.txt?" + query
}

func actionsResultsArtifactURL(host, query string) string {
	return "https://" + host + actionsResultsRun + "/artifacts/" + strings.Repeat("0123456789abcdef", 4) + ".zip?" + query
}

// actionsResultsQuery is the live redirect query: the attestation-shaped SAS
// plus the response overrides GitHub adds for a download.
func actionsResultsQuery(sigSeed string, mutate func(v url.Values)) string {
	return attestationBundleQuery(sigSeed, func(v url.Values) {
		v.Set("rsct", "application/zip")
		v.Set("rscd", `attachment; filename="scorecard-results.zip"`)
		if mutate != nil {
			mutate(v)
		}
	})
}

func newActionsResultsScanner(t *testing.T) (*Scanner, time.Time) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	t.Cleanup(s.Close)
	return s, now
}

// A job log or artifact redirect to one of GitHub's published results
// accounts passes DLP and entropy, with an audience allow recorded for the
// Azure SAS pattern. Any other shape keeps the match.
func TestScan_GitHubActionsResultsSAS(t *testing.T) {
	t.Parallel()
	s, now := newActionsResultsScanner(t)
	query := actionsResultsQuery("actions-results-fixture", nil)

	for name, target := range map[string]string{
		"job log":                 actionsResultsLogURL(actionsResultsHost, query),
		"artifact":                actionsResultsArtifactURL(actionsResultsHost, query),
		"last published account":  actionsResultsLogURL("productionresultssa19.blob.core.windows.net", query),
		"first published account": actionsResultsLogURL("productionresultssa0.blob.core.windows.net", query),
		"long artifact name":      actionsResultsArtifactURL(actionsResultsHost, actionsResultsQuery("actions-results-name", func(v url.Values) { v.Set("rscd", `attachment; filename="`+highEntropyName(255)+`"`) })),
		"artifact name with space": actionsResultsArtifactURL(actionsResultsHost, actionsResultsQuery("actions-results-space", func(v url.Values) {
			v.Set("rscd", `attachment; filename="Test results linux amd64 `+highEntropyName(40)+`.zip"`)
		})),
	} {
		t.Run("allow: "+name, func(t *testing.T) {
			t.Parallel()
			result := s.Scan(context.Background(), target)
			if !result.Allowed {
				t.Fatalf("blocked: scanner=%s reason=%s", result.Scanner, result.Reason)
			}
			found := false
			for _, allow := range result.CredentialAudienceAllows {
				if allow.PatternName == "Azure SAS Token" && allow.Surface == "url" {
					found = true
				}
			}
			if !found {
				t.Fatalf("no Azure SAS Token audience allow recorded: %#v", result.CredentialAudienceAllows)
			}
		})
	}

	cases := []struct {
		name   string
		target string
	}{
		{"account past the published range", actionsResultsLogURL("productionresultssa20.blob.core.windows.net", query)},
		{"other azure account", actionsResultsLogURL("customer.blob.core.windows.net", query)},
		{"artifact at another azure account", actionsResultsArtifactURL("customer.blob.core.windows.net", query)},
		{"lookalike suffix", actionsResultsLogURL(actionsResultsHost+".evil.example", query)},
		{"attestation account on a results path", actionsResultsLogURL("tmaproduction.blob.core.windows.net", query)},
		{"results account on an attestation path", "https://" + actionsResultsHost + "/attestations/1152497359/2026/10/03/52325653.json.sn?" + query},
		{"wrong container", "https://" + actionsResultsHost + "/other" + actionsResultsRun + "/logs/job/job-logs.txt?" + query},
		{"unlisted blob kind", "https://" + actionsResultsHost + actionsResultsRun + "/cache/x.txt?" + query},
		{"bare prefix", "https://" + actionsResultsHost + actionsResultsRun + "/logs/?" + query},
		{"encoded slash", "https://" + actionsResultsHost + actionsResultsRun + "/logs/job%2Fjob-logs.txt?" + query},
		{"traversal", "https://" + actionsResultsHost + actionsResultsRun + "/logs/../../other/x.txt?" + query},
		{"http scheme", strings.Replace(actionsResultsLogURL(actionsResultsHost, query), "https://", "http://", 1)},
		{"sp other than r", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-sp", func(v url.Values) { v.Set("sp", "rw") }))},
		{"container resource", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-sr", func(v url.Values) { v.Set("sr", "c") }))},
		{"missing st", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-st", func(v url.Values) { v.Del("st") }))},
		{"missing delegation key id", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-skoid", func(v url.Values) { v.Del("skoid") }))},
		{"duplicate sig", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-dup", func(v url.Values) { v.Add("sig", releaseGrantSASSig("actions-dup-2")) }))},
		{"lifetime over cap", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-life", func(v url.Values) { v.Set("se", "2026-10-04T21:29:56Z") }))},
		{"expired", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-expired", func(v url.Values) {
			v.Set("st", "2026-10-03T20:00:00Z")
			v.Set("se", "2026-10-03T20:10:00Z")
		}))},
		{"not yet valid", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-future", func(v url.Values) {
			v.Set("st", "2026-10-03T23:00:00Z")
			v.Set("se", "2026-10-03T23:10:00Z")
		}))},
	}
	for _, tc := range cases {
		t.Run("deny: "+tc.name, func(t *testing.T) {
			t.Parallel()
			got := s.Scan(context.Background(), tc.target)
			if got.Allowed {
				t.Fatalf("allowed %s", tc.target)
			}
		})
	}

	// The predicate refuses traversal and a downgrade on its own, so a later
	// reorder of the URL scanner cannot open them.
	for _, p := range []string{"/logs/../../other/x.txt", "/logs/%2e%2e/x.txt", "/logs/./x.txt"} {
		if actionsResultsSASAllowed(actionsResultsHost, "https://"+actionsResultsHost+actionsResultsRun+p+"?"+query, now) {
			t.Fatalf("predicate allowed path %q", p)
		}
	}
	if actionsResultsSASAllowed(actionsResultsHost, strings.Replace(actionsResultsLogURL(actionsResultsHost, query), "https://", "http://", 1), now) {
		t.Fatal("predicate allowed http scheme")
	}

	// The allowance is for the url_query surface only.
	headerCandidate := credentialAudienceCandidate{
		patternName: "Azure SAS Token",
		hosts:       []string{"release-assets.githubusercontent.com"},
		carrierMask: config.CredentialAudienceCarrierReleaseGrantSAS,
	}
	keep, allows := filterCredentialAudience([]credentialAudienceCandidate{headerCandidate}, actionsResultsLogURL(actionsResultsHost, query), "header")
	if len(keep) != 1 || !keep[0] || len(allows) != 0 {
		t.Fatalf("header surface allowed the results SAS: keep=%v allows=%v", keep, allows)
	}
}

// The allow releases the SAS signature and the pinned overrides, nothing else.
// Each credential below is still blocked by its own pattern, and an override
// outside its pin keeps the entropy block.
func TestScan_GitHubActionsResultsSAS_ReleasesOnlySignatureAndPinnedOverrides(t *testing.T) {
	t.Parallel()
	s, _ := newActionsResultsScanner(t)
	aws := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	gh := "ghp_" + strings.Repeat("a", 36)
	query := actionsResultsQuery("actions-carrier", nil)
	if r := s.Scan(context.Background(), actionsResultsArtifactURL(actionsResultsHost, query)); !r.Allowed {
		t.Fatalf("control URL blocked: %s", r.Reason)
	}

	cases := []struct {
		name        string
		target      string
		wantScanner string
	}{
		{"aws key in the blob name", "https://" + actionsResultsHost + actionsResultsRun + "/artifacts/" + aws + ".zip?" + query, ScannerDLP},
		{"github token in the blob name", "https://" + actionsResultsHost + actionsResultsRun + "/artifacts/" + gh + ".zip?" + query, ScannerDLP},
		{"github token in an extra parameter", actionsResultsLogURL(actionsResultsHost, query+"&x="+gh), ScannerDLP},
		{"github token in a signed field", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-skoid", func(v url.Values) { v.Set("skoid", gh) })), ScannerDLP},
		{"github token in the override name", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-rscd", func(v url.Values) { v.Set("rscd", `attachment; filename="`+gh+`"`) })), ScannerDLP},
		{"override name outside the pin", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-pin", func(v url.Values) {
			v.Set("rscd", `attachment; filename="`+highEntropyName(40)+`/`+highEntropyName(40)+`"`)
		})), ScannerEntropy},
		{"unquoted override name", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-unquoted", func(v url.Values) { v.Set("rscd", "attachment; filename="+highEntropyName(60)) })), ScannerEntropy},
		{"override name over 255 bytes", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-long", func(v url.Values) { v.Set("rscd", `attachment; filename="`+highEntropyName(256)+`"`) })), ScannerEntropy},
		{"free text content type", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-rsct", func(v url.Values) { v.Set("rsct", highEntropyName(40)+"/"+highEntropyName(20)) })), ScannerEntropy},
		{"repeated override", actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-repeat", func(v url.Values) { v.Add("rscd", `attachment; filename="`+highEntropyName(60)+`"`) })), ScannerEntropy},
		{"unpinned parameter", actionsResultsLogURL(actionsResultsHost, query+"&x="+highEntropyName(60)), ScannerEntropy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := s.Scan(context.Background(), tc.target)
			if r.Allowed {
				t.Fatalf("allowed %s", tc.target)
			}
			// A critical credential is caught by the immutable core floor, so
			// either DLP label means the credential was still read.
			if r.Scanner != tc.wantScanner && (tc.wantScanner != ScannerDLP || r.Scanner != ScannerCoreDLP) {
				t.Fatalf("blocked by %s (%s), want %s", r.Scanner, r.Reason, tc.wantScanner)
			}
		})
	}
}

// An expired results SAS is named as expired, so an operator who sees the
// block knows to fetch a fresh URL rather than suspect the policy.
func TestQueryGrantValidityCandidate_ActionsResultsSASWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
	expired := actionsResultsQuery("actions-note", func(v url.Values) {
		v.Set("st", "2026-10-03T20:00:00Z")
		v.Set("se", "2026-10-03T20:10:00Z")
	})
	parsed, err := url.Parse(actionsResultsLogURL(actionsResultsHost, expired))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	note, _, ok := queryGrantValidityCandidate(parsed, now)
	if !ok || !strings.Contains(note, "Actions results SAS") {
		t.Fatalf("note = %q ok=%v, want the Actions results SAS window note", note, ok)
	}

	live, err := url.Parse(actionsResultsLogURL(actionsResultsHost, actionsResultsQuery("actions-live", nil)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if note, _, ok := queryGrantValidityCandidate(live, now); ok {
		t.Fatalf("live SAS produced a window note: %q", note)
	}
}

func TestActionsResultsURLAdversarialForms(t *testing.T) {
	s, _ := newActionsResultsScanner(t)
	good := actionsResultsArtifactURL(actionsResultsHost, actionsResultsQuery("review-control", nil))
	for _, tc := range []struct {
		name, target string
		allow        bool
	}{
		{"control", good, true},
		{"uppercase host", strings.Replace(good, actionsResultsHost, strings.ToUpper(actionsResultsHost), 1), true},
		{"trailing dot", strings.Replace(good, actionsResultsHost, actionsResultsHost+".", 1), true},
		{"explicit port", strings.Replace(good, actionsResultsHost, actionsResultsHost+":443", 1), true},
		{"encoded unique override key", strings.Replace(good, "rscd=", "%72scd=", 1), true},
		{"userinfo", strings.Replace(good, "https://", "https://user@", 1), false},
		{"lookalike", strings.Replace(good, actionsResultsHost, "productionresultssa1.blob.core.windows.net.vendor.example", 1), false},
		{"IDN lookalike", strings.Replace(good, actionsResultsHost, "productionresultssа1.blob.core.windows.net", 1), false},
		{"encoded duplicate", good + "&%72scd=" + url.QueryEscape(`attachment; filename="`+highEntropyName(60)+`"`), false},
		{"case alias", good + "&RSCD=" + url.QueryEscape(`attachment; filename="`+highEntropyName(60)+`"`), false},
		{"encoded duplicate signature", good + "&%73ig=" + url.QueryEscape(releaseGrantSASSig("review-duplicate")), false},
		{"semicolon ambiguity", good + ";x=" + highEntropyName(60), false},
		{"credential fragment", good + "#sig=" + url.QueryEscape(releaseGrantSASSig("review-fragment")), false},
		{"high entropy path", strings.Replace(good, "/artifacts/", "/artifacts/"+highEntropyName(200)+"/", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Scan(context.Background(), tc.target)
			if got.Allowed != tc.allow {
				t.Fatalf("allowed=%v want=%v scanner=%s reason=%s", got.Allowed, tc.allow, got.Scanner, got.Reason)
			}
		})
	}
}
