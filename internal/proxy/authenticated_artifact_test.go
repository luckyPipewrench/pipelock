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
	"errors"
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

type artifactErrorBody struct {
	readErr  error
	closeErr error
}

func (b artifactErrorBody) Read([]byte) (int, error) { return 0, b.readErr }
func (b artifactErrorBody) Close() error             { return b.closeErr }

type artifactCloseErrorBody struct {
	io.Reader
	closeErr error
}

func (b artifactCloseErrorBody) Close() error { return b.closeErr }

func TestVerifyAuthenticatedArtifact_FailsClosedForVerifierErrors(t *testing.T) {
	priv := installArtifactOfficialKey(t)
	validBody := artifactBundle("test")
	validSig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, validBody)))
	_, unofficialPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongNameBody := bytes.Replace(validBody, []byte("name: pipelock-community"), []byte("name: other-bundle"), 1)
	u, err := url.Parse("https://rules.example/rules/pipelock-community/bundle.yaml")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Method: http.MethodGet, URL: u}
	entries := []config.AuthenticatedArtifactEntry{{Host: u.Host, Path: u.Path, BundleName: "pipelock-community"}}

	signatureResponse := func(body io.ReadCloser) *http.Response {
		sigURL := *u
		sigURL.Path += ".sig"
		sigReq := req.Clone(t.Context())
		sigReq.URL = &sigURL
		return &http.Response{StatusCode: http.StatusOK, Body: body, Request: sigReq}
	}
	signedTransport := func(sig []byte) http.RoundTripper {
		return artifactRoundTripper(func(*http.Request) (*http.Response, error) {
			return signatureResponse(io.NopCloser(bytes.NewReader(sig))), nil
		})
	}
	for _, tc := range []struct {
		name string
		resp *http.Response
		rt   http.RoundTripper
	}{
		{
			name: "default transport still rejects redirect",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(nil)), Request: &http.Request{URL: &url.URL{Scheme: "https", Host: u.Host, Path: "/other"}}},
		},
		{name: "upstream status", resp: &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewReader(nil)), Request: req}},
		{name: "bundle read", resp: &http.Response{StatusCode: http.StatusOK, Body: artifactErrorBody{readErr: errors.New("bundle read failed")}, Request: req}},
		{name: "bundle too large", resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), domrules.MaxBundleFileSize+1))), Request: req}},
		{
			name: "signature transport",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(validBody)), Request: req},
			rt:   artifactRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("signature transport failed") }),
		},
		{
			name: "signature read",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(validBody)), Request: req},
			rt: artifactRoundTripper(func(*http.Request) (*http.Response, error) {
				return signatureResponse(artifactErrorBody{readErr: errors.New("signature read failed")}), nil
			}),
		},
		{
			name: "untrusted signer",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(validBody)), Request: req},
			rt:   signedTransport([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(unofficialPriv, validBody)))),
		},
		{
			name: "bundle parse",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("not a bundle"))), Request: req},
			rt: artifactRoundTripper(func(*http.Request) (*http.Response, error) {
				body := []byte("not a bundle")
				return signatureResponse(io.NopCloser(bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body)))))), nil
			}),
		},
		{
			name: "bundle identity",
			resp: &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(wrongNameBody)), Request: req},
			rt:   signedTransport([]byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, wrongNameBody)))),
		},
		{
			name: "upstream close",
			resp: &http.Response{StatusCode: http.StatusOK, Body: artifactCloseErrorBody{Reader: bytes.NewReader(validBody), closeErr: errors.New("close failed")}, Request: req},
			rt:   signedTransport(validSig),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() { _ = tc.resp.Body.Close() }()
			if tc.rt == nil && tc.name != "default transport still rejects redirect" && tc.name != "upstream status" && tc.name != "bundle read" && tc.name != "bundle too large" {
				t.Fatal("test setup omitted a signature transport")
			}
			artifact, err := verifyAuthenticatedArtifact(t.Context(), req, tc.resp, tc.rt, entries)
			if err == nil || artifact != nil {
				t.Fatalf("artifact=%v err=%v, want fail closed", artifact, err)
			}
		})
	}
}
