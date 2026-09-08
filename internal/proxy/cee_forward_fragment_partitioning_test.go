// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const ceeForwardConversationPaddingBytes = 40 * 1024

func TestForwardCEEFragmentReassemblyPartitionsJSONBodyFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.CrossRequestDetection.Enabled = true
		cfg.CrossRequestDetection.Action = config.ActionBlock
		cfg.CrossRequestDetection.EntropyBudget.Enabled = false
		cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
		cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 2 * ceeForwardConversationPaddingBytes
		cfg.RequestBodyScanning.Enabled = false
	})
	t.Cleanup(cleanup)

	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "api.vendor.example:80" {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	client := forwardHTTPClient(t, proxyAddr)
	t.Cleanup(client.CloseIdleConnections)

	secret := testCEEAWSKeyPrefix + testCEEAWSKeySuffix
	half := len(secret) / 2
	first, second := secret[:half], secret[half:]

	t.Run("interleaved conversations block on the completing request", func(t *testing.T) {
		firstResponse := forwardCEEJSONPost(t, client, first, strings.Repeat("ordinary prose ", ceeForwardConversationPaddingBytes/len("ordinary prose ")))
		defer func() { _ = firstResponse.Body.Close() }()
		if firstResponse.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(firstResponse.Body)
			t.Fatalf("first status = %d, want 200; body=%s", firstResponse.StatusCode, body)
		}

		secondResponse := forwardCEEJSONPost(t, client, second, strings.Repeat("ordinary prose ", ceeForwardConversationPaddingBytes/len("ordinary prose ")))
		defer func() { _ = secondResponse.Body.Close() }()
		if secondResponse.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(secondResponse.Body)
			t.Fatalf("completing status = %d, want 403; body=%s", secondResponse.StatusCode, body)
		}
	})

	t.Run("sole body content control still blocks", func(t *testing.T) {
		ResetCEEState("", "127.0.0.1", nil, p.fragmentBufferPtr.Load())
		firstResponse := forwardCEETextPost(t, client, first)
		defer func() { _ = firstResponse.Body.Close() }()
		if firstResponse.StatusCode != http.StatusOK {
			t.Fatalf("first status = %d, want 200", firstResponse.StatusCode)
		}

		secondResponse := forwardCEETextPost(t, client, second)
		defer func() { _ = secondResponse.Body.Close() }()
		if secondResponse.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(secondResponse.Body)
			t.Fatalf("completing status = %d, want 403; body=%s", secondResponse.StatusCode, body)
		}
	})
}

func forwardCEEJSONPost(t *testing.T, client *http.Client, content, padding string) *http.Response {
	t.Helper()
	body := `{"messages":[{"role":"user","content":"` + content + `"}],"history":"` + padding + `"}`
	return forwardCEEPost(t, client, body, "application/json")
}

func forwardCEETextPost(t *testing.T, client *http.Client, body string) *http.Response {
	t.Helper()
	return forwardCEEPost(t, client, body, "text/plain")
}

func forwardCEEPost(t *testing.T, client *http.Client, body, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new forward request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	return resp
}
