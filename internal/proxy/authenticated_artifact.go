// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type authenticatedArtifactResponse struct {
	body []byte
}

func matchingAuthenticatedArtifact(req *http.Request, entries []config.AuthenticatedArtifactEntry) (config.AuthenticatedArtifactEntry, bool) {
	if req == nil || req.Method != http.MethodGet || req.URL == nil || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.Fragment != "" || (req.URL.Port() != "" && req.URL.Port() != "443") {
		return config.AuthenticatedArtifactEntry{}, false
	}
	for _, entry := range entries {
		if strings.EqualFold(req.URL.Hostname(), entry.Host) && req.URL.EscapedPath() == entry.Path {
			return entry, true
		}
	}
	return config.AuthenticatedArtifactEntry{}, false
}

// verifyAuthenticatedArtifact releases only exact operator-configured rule
// artifacts which the proxy itself has verified against the embedded keyring.
func verifyAuthenticatedArtifact(ctx context.Context, req *http.Request, resp *http.Response, rt http.RoundTripper, entries []config.AuthenticatedArtifactEntry) (*authenticatedArtifactResponse, error) {
	entry, ok := matchingAuthenticatedArtifact(req, entries)
	if !ok {
		return nil, nil
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	if resp == nil || resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.String() != req.URL.String() {
		return nil, fmt.Errorf("authenticated artifact refused: redirect")
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("authenticated artifact refused: upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, domrules.MaxBundleFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact read: %w", err)
	}
	if len(body) > domrules.MaxBundleFileSize {
		return nil, fmt.Errorf("authenticated artifact refused: bundle exceeds %d bytes", domrules.MaxBundleFileSize)
	}
	sigURL := *req.URL
	sigURL.Path += signing.SigExtension
	sigURL.RawPath = ""
	sigReq := req.Clone(ctx)
	sigReq.URL, sigReq.RequestURI, sigReq.Body, sigReq.GetBody = &sigURL, "", nil, nil
	sigReq.Host = ""
	sigReq.Header = make(http.Header)
	sigResp, err := rt.RoundTrip(sigReq)
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact signature fetch: %w", err)
	}
	defer func() { _ = sigResp.Body.Close() }()
	if sigResp.Request == nil || sigResp.Request.URL == nil || sigResp.Request.URL.String() != sigURL.String() || sigResp.StatusCode < http.StatusOK || sigResp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("authenticated artifact refused: signature redirect or status")
	}
	sigData, err := io.ReadAll(io.LimitReader(sigResp.Body, 4097))
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact signature read: %w", err)
	}
	if len(sigData) > 4096 {
		return nil, fmt.Errorf("authenticated artifact refused: signature exceeds 4096 bytes")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact signature decode: %w", err)
	}
	result, err := domrules.VerifyBundleSignatureBytes(body, sig, domrules.TrustPolicy{TrustEmbeddedKeys: true})
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact signature verification: %w", err)
	}
	if result.Tier != domrules.TrustTierOfficial {
		return nil, fmt.Errorf("authenticated artifact signature verification: signer is not official")
	}
	bundle, err := domrules.ParseBundle(body)
	if err != nil {
		return nil, fmt.Errorf("authenticated artifact parse: %w", err)
	}
	if bundle.Name != entry.BundleName {
		return nil, fmt.Errorf("authenticated artifact identity mismatch: got %q, want %q", bundle.Name, entry.BundleName)
	}
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("authenticated artifact close upstream body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return &authenticatedArtifactResponse{body: body}, nil
}
