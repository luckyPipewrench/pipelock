// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func attestationBundleQuery(sigSeed string, mutate func(v url.Values)) string {
	v := url.Values{}
	v.Set("sp", "r")
	v.Set("sv", "2026-12-06")
	v.Set("sr", "b")
	v.Set("spr", "https")
	v.Set("st", "2026-10-03T21:29:55Z")
	v.Set("se", "2026-10-03T22:29:55Z")
	v.Set("skoid", "322a4be5-8e0b-4548-9b48-4e436a2c7c75")
	v.Set("sktid", "398a6654-997b-47e9-b12b-9515b896b4de")
	v.Set("skt", "2026-10-03T21:37:39Z")
	v.Set("ske", "2026-10-03T23:37:39Z")
	v.Set("sks", "b")
	v.Set("skv", "2026-12-06")
	v.Set("sig", releaseGrantSASSig(sigSeed))
	if mutate != nil {
		mutate(v)
	}
	return v.Encode()
}

func attestationBundleURL(host, query string) string {
	return "https://" + host + "/attestations/1152497359/2026/10/03/52325653.json.sn?" + query
}

func TestScan_GitHubAttestationBundleSAS(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()

	query := attestationBundleQuery("bundle-sas-fixture", nil)
	target := attestationBundleURL("tmaproduction.blob.core.windows.net", query)
	result := s.Scan(context.Background(), target)
	if !result.Allowed {
		t.Fatalf("attestation bundle SAS blocked: scanner=%s reason=%s", result.Scanner, result.Reason)
	}
	found := false
	for _, allow := range result.CredentialAudienceAllows {
		if allow.PatternName == "Azure SAS Token" && allow.Surface == "url" && allow.Destination == "tmaproduction.blob.core.windows.net" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audience allows = %#v", result.CredentialAudienceAllows)
	}

	cases := []struct {
		name   string
		target string
	}{
		{
			name:   "other azure account",
			target: attestationBundleURL("customer.blob.core.windows.net", query),
		},
		{
			name:   "wrong path",
			target: "https://tmaproduction.blob.core.windows.net/other/1152497359/blob.json.sn?" + query,
		},
		{
			name: "sp other than r",
			target: attestationBundleURL("tmaproduction.blob.core.windows.net", attestationBundleQuery("bundle-sp", func(v url.Values) {
				v.Set("sp", "rw")
			})),
		},
		{
			name: "missing st",
			target: attestationBundleURL("tmaproduction.blob.core.windows.net", attestationBundleQuery("bundle-st", func(v url.Values) {
				v.Del("st")
			})),
		},
		{
			name: "missing sig",
			target: attestationBundleURL("tmaproduction.blob.core.windows.net", attestationBundleQuery("bundle-sig", func(v url.Values) {
				v.Del("sig")
				v.Set("sigx", releaseGrantSASSig("bundle-sig"))
			})),
		},
		{
			name: "lifetime over cap",
			target: attestationBundleURL("tmaproduction.blob.core.windows.net", attestationBundleQuery("bundle-life", func(v url.Values) {
				v.Set("se", "2026-10-04T21:29:56Z")
			})),
		},
		{
			name:   "http scheme",
			target: "http://tmaproduction.blob.core.windows.net/attestations/1152497359/2026/10/03/52325653.json.sn?" + query,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := s.Scan(context.Background(), tc.target)
			if got.Allowed {
				t.Fatalf("allowed %s", tc.target)
			}
			if !strings.Contains(got.Reason, "Azure SAS Token") && tc.name != "missing sig" && tc.name != "http scheme" {
				t.Fatalf("reason = %q, want Azure SAS Token", got.Reason)
			}
		})
	}

	headerCandidate := credentialAudienceCandidate{
		patternName: "Azure SAS Token",
		hosts:       []string{"release-assets.githubusercontent.com"},
		carrierMask: config.CredentialAudienceCarrierReleaseGrantSAS,
	}
	keep, allows := filterCredentialAudience([]credentialAudienceCandidate{headerCandidate}, target, "header")
	if len(keep) != 1 || !keep[0] || len(allows) != 0 {
		t.Fatalf("header surface allowed attestation SAS: keep=%v allows=%v", keep, allows)
	}

	// The documented staging account uses the same shape. A day-long window
	// matches the REST example and stays inside the measured cap.
	staging := attestationBundleURL("tmastaging.blob.core.windows.net", attestationBundleQuery("bundle-staging", func(v url.Values) {
		v.Set("st", "2024-11-08T17:13:43Z")
		v.Set("se", "2024-11-09T17:13:43Z")
		v.Set("spr", "https")
	}))
	staged := s.Scan(context.Background(), staging)
	if !staged.Allowed {
		t.Fatalf("staging bundle SAS blocked: scanner=%s reason=%s", staged.Scanner, staged.Reason)
	}
}
