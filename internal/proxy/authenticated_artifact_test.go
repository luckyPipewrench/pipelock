// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

type artifactRoundTripper func(*http.Request) (*http.Response, error)

func (f artifactRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifyAuthenticatedArtifact_VerifiesBeforeReleaseAndStripsCallerHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	origDefault, origKeyring := domrules.DefaultKeyringHex, domrules.KeyringHex
	domrules.DefaultKeyringHex, domrules.KeyringHex = hex.EncodeToString(pub), ""
	t.Cleanup(func() { domrules.DefaultKeyringHex, domrules.KeyringHex = origDefault, origKeyring })
	body := []byte("format_version: 1\nname: pipelock-community\nversion: 2026.08.0\nauthor: test\ndescription: test bundle\nrules: []\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)))
	u, _ := url.Parse("https://rules.example/rules/pipelock-community/bundle.yaml")
	req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{"Authorization": {"Bearer caller"}, "Cookie": {"session=caller"}}}
	resp := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Request: req}
	rt := artifactRoundTripper(func(got *http.Request) (*http.Response, error) {
		if got.Header.Get("Authorization") != "" || got.Header.Get("Cookie") != "" {
			t.Fatalf("sidecar copied caller credentials: %v", got.Header)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(sig)), Request: got}, nil
	})
	artifact, err := verifyAuthenticatedArtifact(context.Background(), req, resp, rt, []config.AuthenticatedArtifactEntry{{Host: "rules.example", Path: "/rules/pipelock-community/bundle.yaml", BundleName: "pipelock-community"}})
	if err != nil {
		t.Fatalf("verifyAuthenticatedArtifact() error: %v", err)
	}
	if artifact == nil || !bytes.Equal(artifact.body, body) {
		t.Fatalf("verified artifact = %#v, want original bytes", artifact)
	}
}

func TestVerifyAuthenticatedArtifact_FailsClosedForTamperAndRedirect(t *testing.T) {
	u, _ := url.Parse("https://rules.example/rules/pipelock-community/bundle.yaml")
	req := &http.Request{Method: http.MethodGet, URL: u}
	entries := []config.AuthenticatedArtifactEntry{{Host: "rules.example", Path: u.Path, BundleName: "pipelock-community"}}
	for _, tc := range []struct {
		name string
		resp *http.Response
	}{
		{name: "redirect", resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Request: &http.Request{URL: &url.URL{Scheme: "https", Host: "rules.example", Path: "/other"}}}},
		{name: "tamper", resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("not a bundle"))), Request: req}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact, err := verifyAuthenticatedArtifact(context.Background(), req, tc.resp, artifactRoundTripper(func(got *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("bad"))), Request: got}, nil
			}), entries)
			if err == nil || artifact != nil {
				t.Fatalf("artifact=%v err=%v, want fail closed", artifact, err)
			}
		})
	}
}

func TestMatchingAuthenticatedArtifact_RejectsMethodQueryAndNonDefaultPort(t *testing.T) {
	entries := []config.AuthenticatedArtifactEntry{{Host: "rules.example", Path: "/rules/pipelock-community/bundle.yaml", BundleName: "pipelock-community"}}
	for _, raw := range []string{
		"https://rules.example/rules/pipelock-community/bundle.yaml?next=x",
		"https://rules.example:444/rules/pipelock-community/bundle.yaml",
		"https://rules.example/rules/pipelock-community/bundle.yaml/extra",
	} {
		u, _ := url.Parse(raw)
		if _, ok := matchingAuthenticatedArtifact(&http.Request{Method: http.MethodGet, URL: u}, entries); ok {
			t.Fatalf("matched unsafe URL %q", raw)
		}
	}
	defaultPort, _ := url.Parse("https://rules.example:443/rules/pipelock-community/bundle.yaml")
	if _, ok := matchingAuthenticatedArtifact(&http.Request{Method: http.MethodGet, URL: defaultPort}, entries); !ok {
		t.Fatal("explicit HTTPS default port did not match")
	}
	u, _ := url.Parse("https://rules.example/rules/pipelock-community/bundle.yaml")
	if _, ok := matchingAuthenticatedArtifact(&http.Request{Method: http.MethodPost, URL: u}, entries); ok {
		t.Fatal("matched non-GET request")
	}
}
