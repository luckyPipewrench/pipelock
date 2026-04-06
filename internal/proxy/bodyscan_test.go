// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testMultipartBoundary = "----testboundary"
)

// testScannerConfig returns a config suitable for body scan tests.
// SSRF is disabled (Internal=nil) to avoid DNS lookups in unit tests.
func testScannerConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024 // 1MB for tests
	cfg.ApplyDefaults()                                // populates SensitiveHeaders, HeaderMode, IgnoreHeaders
	return cfg
}

// fakeAPIKey builds a fake AWS key at runtime to avoid triggering DLP
// on the test source itself.
func fakeAPIKey() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func TestScanRequestBody_JSONWithSecret(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"key": "` + fakeAPIKey() + `"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in JSON body with API key")
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected non-empty DLP matches")
	}
}

func TestScanRequestBody_JSONKeyExfil(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// Secret encoded as a JSON object key
	body := `{"` + fakeAPIKey() + `": "value"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in JSON key")
	}
}

func TestScanRequestBody_FormURLEncoded(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := "secret=" + fakeAPIKey() + "&name=test"
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/x-www-form-urlencoded",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in form body")
	}
}

func TestScanRequestBody_PlainText(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := "my secret key is " + fakeAPIKey()
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "text/plain",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in plain text body")
	}
}

func TestScanRequestBody_ContentTypeBypass_OctetStream(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// JSON secret sent as application/octet-stream: fallback raw scan catches it
	body := `{"key": "` + fakeAPIKey() + `"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/octet-stream",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match via fallback raw scan on octet-stream")
	}
}

func TestScanRequestBody_ContentTypeBypass_ImagePNG(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// JSON secret sent as image/png: fallback raw scan catches it
	body := `{"key": "` + fakeAPIKey() + `"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "image/png",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match via fallback raw scan on image/png")
	}
}

func TestScanRequestBody_CompressedGzip(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader("compressed data"),
		ContentType:     "application/json",
		ContentEncoding: "gzip",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block on gzip Content-Encoding")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %q", result.Action)
	}
}

func TestScanRequestBody_CompressedDeflate(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader("compressed data"),
		ContentType:     "application/json",
		ContentEncoding: "deflate",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block on deflate")
	}
}

func TestScanRequestBody_CompressedCaseMismatch(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader("data"),
		ContentType:     "application/json",
		ContentEncoding: "GZip",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block on case-insensitive gzip")
	}
}

func TestScanRequestBody_CompressedCommaSeparated(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader("data"),
		ContentType:     "application/json",
		ContentEncoding: "gzip, identity",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block on comma-separated with gzip")
	}
}

func TestScanRequestBody_IdentityEncodingAllowed(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:            strings.NewReader("clean body text"),
		ContentType:     "text/plain",
		ContentEncoding: "identity",
		MaxBytes:        cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:         sc,
	})
	if !result.Clean {
		t.Fatal("identity encoding should be allowed")
	}
}

func TestScanRequestBody_EmptyBody(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(""),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Fatal("empty body should be clean")
	}
	if len(buf) != 0 {
		t.Fatal("expected empty buffer")
	}
}

func TestScanRequestBody_OversizedBody(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// Create body larger than 1MB max
	body := strings.Repeat("x", cfg.RequestBodyScanning.MaxBodyBytes+1)
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "text/plain",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block on oversized body")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %q", result.Action)
	}
}

func TestScanRequestBody_SplitSecretAcrossFields(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// Split an API key across two JSON fields
	key := fakeAPIKey()
	half1 := key[:len(key)/2]
	half2 := key[len(key)/2:]
	body := `{"part1": "` + half1 + `", "part2": "` + half2 + `"}`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match from joined scan of split secret")
	}
}

func TestScanRequestBody_CleanJSON(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"name": "test", "value": 42}`
	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Fatal("clean JSON body should not trigger DLP")
	}
	if string(buf) != body {
		t.Fatal("buffered body should match original")
	}
}

func TestScanRequestBody_XMLWithSecret(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `<root><key>` + fakeAPIKey() + `</key></root>`
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "application/xml",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in XML body")
	}
}

func TestScanRequestBody_MultipartText(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"field1\"\r\n\r\n" +
		fakeAPIKey() + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in multipart text field")
	}
}

func TestScanRequestBody_MultipartBinarySkipped(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"image.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"\x89PNG\r\n\x1a\n" + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if !result.Clean {
		t.Fatal("binary multipart part should be skipped")
	}
}

// TestScanRequestBody_MultipartBinaryMetadataExfil verifies that secrets in
// binary part metadata (filename) are detected even when the binary body is skipped.
func TestScanRequestBody_MultipartBinaryMetadataExfil(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	secretFilename := fakeAPIKey() + ".png"
	boundary := testMultipartBoundary
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"" + secretFilename + "\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"\x89PNG\r\n\x1a\n" + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match for secret in binary part filename")
	}
}

// --- Header scanning tests ---

func TestScanRequestHeaders_AuthorizationBearer(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match in Authorization header")
	}
}

func TestScanRequestHeaders_Cookie(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("Cookie", "session="+fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match in Cookie header")
	}
}

func TestScanRequestHeaders_XApiKey(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("X-Api-Key", fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match in X-Api-Key header")
	}
}

func TestScanRequestHeaders_CustomHeaderSensitiveMode(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("X-Custom-Exfil", fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result != nil {
		t.Fatal("custom header should not be scanned in sensitive mode")
	}
}

func TestScanRequestHeaders_CustomHeaderAllMode(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("X-Custom-Exfil", fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match in custom header in all mode")
	}
}

func TestScanRequestHeaders_HopByHopIgnoredInAllMode(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	// Transfer-Encoding is in the ignore list, should not be scanned.
	headers.Set("Transfer-Encoding", fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result != nil {
		t.Fatal("hop-by-hop header should be ignored in all mode")
	}
}

func TestScanRequestHeaders_EmptyHeaders(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	result := scanRequestHeaders(context.Background(), http.Header{}, cfg, sc)
	if result != nil {
		t.Fatal("empty headers should be clean")
	}
}

func TestScanRequestHeaders_SplitSecretAcrossHeaders(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	sc := scanner.New(cfg)
	defer sc.Close()

	key := fakeAPIKey()
	half1 := key[:len(key)/2]
	half2 := key[len(key)/2:]

	headers := http.Header{}
	headers.Set("X-Part-A", half1)
	headers.Set("X-Part-B", half2)

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match from joined scan of split secret across headers")
	}
}

func TestScanRequestHeaders_SplitSecretRepeatedValues(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	key := fakeAPIKey()
	half1 := key[:len(key)/2]
	half2 := key[len(key)/2:]

	headers := http.Header{}
	headers.Add("Authorization", half1)
	headers.Add("Authorization", half2)

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match from joined scan of repeated header values")
	}
}

// TestScanRequestHeaders_AllowlistedHost verifies that header scanning applies
// regardless of destination host. The allowlist controls URL-level blocking, not
// header DLP bypass.
func TestScanRequestHeaders_AllowlistedHost(t *testing.T) {
	cfg := testScannerConfig()
	// Simulate an allowlisted host by adding the test host to the allowlist.
	// Header scanning must still detect secrets.
	cfg.APIAllowlist = []string{"*.example.com", "api.anthropic.com"}
	sc := scanner.New(cfg)
	defer sc.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+fakeAPIKey())

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match for secret in Authorization header (allowlist must not bypass header DLP)")
	}
}

// TestScanRequestHeaders_NameValueBoundarySplit verifies that a secret split
// across a header name and its value is caught via the joined scan in all mode.
func TestScanRequestHeaders_NameValueBoundarySplit(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
	sc := scanner.New(cfg)
	defer sc.Close()

	// Split a fake AWS key across header name and value.
	// The key prefix goes into the header name, the rest into the value.
	// Individual scans won't match, but joined scan should.
	headers := http.Header{}
	headers.Set("X-"+"AKIA"+"IOSFODNN", "7EXAMPLE"+"ABCDEFGH")

	result := scanRequestHeaders(context.Background(), headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match for secret split across header name and value boundary")
	}
}

// TestScanRequestBody_ChunkedTransfer verifies that chunked bodies
// (ContentLength == -1) are still scanned.
func TestScanRequestBody_ChunkedTransfer(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"token": "` + fakeAPIKey() + `"}`
	// Simulate chunked encoding by using a reader without known length.
	reader := strings.NewReader(body)

	buf, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        reader,
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match in chunked JSON body")
	}
	if buf == nil {
		t.Fatal("expected buffered body even on match")
	}
}

// --- Integration tests ---

func TestForwardProxy_BodyScan_BlockMode(t *testing.T) {
	// Start an upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	// POST with secret body through forward proxy
	body := `{"key": "` + fakeAPIKey() + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 for body with secret, got %d: %s", resp.StatusCode, respBody)
	}
}

func TestForwardProxy_BodyScan_CleanBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	body := `{"name": "test", "value": 42}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for clean body, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_BodyScan_OversizedBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	maxBytes := 1024 // 1KB for test
	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn // even warn mode blocks oversized
		cfg.RequestBodyScanning.MaxBodyBytes = maxBytes
	})
	defer cleanup()

	body := strings.Repeat("x", maxBytes+1)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Oversized bodies are always blocked regardless of action setting.
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for oversized body, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_BodyScan_WarnMode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	body := `{"key": "` + fakeAPIKey() + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Warn mode: request should be forwarded despite DLP match.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 in warn mode, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_GzipContentEncoding_Blocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Encoding", "gzip")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for gzip body, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_OctetStreamBypass_Blocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	body := `{"key": "` + fakeAPIKey() + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for octet-stream with secret, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_HeaderScan_SecretInAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+fakeAPIKey())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for header with secret, got %d", resp.StatusCode)
	}
}

func TestForwardProxy_SplitSecretHeaders_Blocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyAddr, cleanup := setupForwardProxy(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionBlock
		cfg.RequestBodyScanning.ScanHeaders = true
		cfg.RequestBodyScanning.HeaderMode = config.HeaderModeAll
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
	})
	defer cleanup()

	key := fakeAPIKey()
	half1 := key[:len(key)/2]
	half2 := key[len(key)/2:]

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Part-A", half1)
	req.Header.Set("X-Part-B", half2)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for split secret across headers, got %d", resp.StatusCode)
	}
}

// --- Fetch handler header test ---

func TestFetchHandler_HeaderScan_SecretInAuth(t *testing.T) {
	// Test that the fetch handler also scans headers.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.ApplyDefaults() // re-apply after enabling features with conditional defaults

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// Create a request to the fetch handler with a secret in the header.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL, nil)
	req.Header.Set("Authorization", "Bearer "+fakeAPIKey())
	w := httptest.NewRecorder()

	p.handleFetch(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from fetch handler for header with secret, got %d", w.Code)
	}
}

func TestFetchHandler_HeaderScan_WarnMode(t *testing.T) {
	// In warn mode, fetch handler should allow the request but still log.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.APIAllowlist = []string{"*"} // allow all URLs so we reach header scanning
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.ApplyDefaults()
	cfg.Internal = nil // disable SSRF after ApplyDefaults (avoids localhost block)

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL, nil)
	req.Header.Set("Authorization", "Bearer "+fakeAPIKey())
	w := httptest.NewRecorder()

	p.handleFetch(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from fetch handler in warn mode, got %d", w.Code)
	}
}

// --- hasNonIdentityEncoding tests ---

func TestHasNonIdentityEncoding(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", false},
		{"identity", false},
		{"Identity", false},
		{"gzip", true},
		{"deflate", true},
		{"br", true},
		{"GZip", true},
		{"gzip, identity", true},
		{"identity, identity", false},
		{" identity ", false},
		{"compress", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hasNonIdentityEncoding(tt.input)
			if got != tt.want {
				t.Errorf("hasNonIdentityEncoding(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- Invalid JSON fail-closed ---

func TestScanRequestBody_InvalidJSON_FailClosed(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// Invalid JSON declared as application/json must fail-closed (not pass as clean).
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(`{invalid json`),
		ContentType: "application/json",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block for invalid JSON body")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action for invalid JSON, got %q", result.Action)
	}
}

// --- extractFormURLEncoded edge cases ---

func TestScanRequestBody_FormURLEncoded_ParseFailure(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// Malformed query string that url.ParseQuery rejects: bare % without hex digits.
	// Fail-closed: parse error blocks regardless of body content.
	malformed := "field=%zz&value=clean"
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(malformed),
		ContentType: "application/x-www-form-urlencoded",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block for malformed form body")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action for form parse error, got %q", result.Action)
	}
}

func TestScanRequestBody_MultipartMissingBoundary(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	// multipart/form-data without boundary parameter: fail-closed block.
	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader("some body content"),
		ContentType: "multipart/form-data",
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block for multipart missing boundary")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action for missing boundary, got %q", result.Action)
	}
}

func TestScanRequestBody_MultipartOversizedFilename(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	// Filename exceeding maxFilenameBytes (256): fail-closed block.
	longFilename := strings.Repeat("x", maxFilenameBytes+1)
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"" + longFilename + "\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"clean content\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block for oversized multipart filename")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action for oversized filename, got %q", result.Action)
	}
}

// --- extractMultipart edge cases ---

func TestScanRequestBody_MultipartOversizedPart(t *testing.T) {
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.MaxBodyBytes = 500
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	// Create a part body larger than maxBodyBytes (500).
	bigValue := strings.Repeat("A", 501)
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"data\"\r\n\r\n" +
		bigValue + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block for oversized multipart part")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %q", result.Action)
	}
}

func TestScanRequestBody_MultipartFilename(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	// Put a secret in the filename field (exfil via metadata).
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"upload\"; filename=\"" + "AKIA" + "IOSFODNN7EXAMPLE" + "ABCDEFGH.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"clean content\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match for secret in multipart filename")
	}
}

func TestScanRequestBody_MultipartBinaryWithMetadata(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	// Binary part (image/png) with secret in form name.
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"" + "AKIA" + "IOSFODNN7EXAMPLE" + "ABCDEFGH\"; filename=\"photo.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"\x89PNG\r\n\x1a\n\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match for secret in binary part form name")
	}
}

// --- isNoisyHeaderName coverage ---

func TestIsNoisyHeaderName(t *testing.T) {
	tests := []struct {
		name  string
		noisy bool
	}{
		{"Sec-Fetch-Site", true},
		{"Sec-Ch-Ua", true},
		{"X-Forwarded-For", true},
		{"X-Forwarded-Proto", true},
		{"Traceparent", true},
		{"Tracestate", true},
		{"X-Request-Id", true},
		{"X-Trace-Id", true},
		{"X-Correlation-Id", true},
		{"X-Amzn-Trace-Id", true},
		{"Authorization", false},
		{"Cookie", false},
		{"X-Custom-Header", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoisyHeaderName(tt.name); got != tt.noisy {
				t.Errorf("isNoisyHeaderName(%q) = %v, want %v", tt.name, got, tt.noisy)
			}
		})
	}
}

// --- Multipart limit tests ---

func TestScanRequestBody_MultipartTooManyParts(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	var sb strings.Builder
	// Create 101 parts (exceeds maxMultipartParts of 100)
	for i := 0; i <= maxMultipartParts; i++ {
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString("Content-Disposition: form-data; name=\"field" + strings.Repeat("x", 1) + "\"\r\n\r\n")
		sb.WriteString("value\r\n")
	}
	sb.WriteString("--" + boundary + "--\r\n")

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(sb.String()),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected fail-closed block when multipart part limit exceeded")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action for multipart limit, got %q", result.Action)
	}
}

// --- isBinaryContentType unit tests ---

func TestIsBinaryContentType(t *testing.T) {
	tests := []struct {
		ct     string
		binary bool
	}{
		{"", false},
		{"text/plain", false},
		{"text/html", false},
		{"application/json", false},
		{"application/xml", false},
		{"application/octet-stream", false}, // fallback raw scan, not skipped
		{"image/png", true},
		{"image/jpeg", true},
		{"image/gif", true},
		{"audio/mpeg", true},
		{"audio/ogg", true},
		{"video/mp4", true},
		{"video/webm", true},
		{"application/pdf", false},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			if got := isBinaryContentType(tt.ct); got != tt.binary {
				t.Errorf("isBinaryContentType(%q) = %v, want %v", tt.ct, got, tt.binary)
			}
		})
	}
}

// fakeAnthropicKey builds a fake Anthropic API key at runtime to avoid
// triggering DLP on the test source itself (gosec G101).
func fakeAnthropicKey() string {
	return "sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}

// --- Multipart DLP bypass exploit tests ---
//
// These prove that multipart DLP scanning cannot be bypassed via
// Content-Type spoofing, custom part headers, or Content-Transfer-Encoding.

func TestExtractMultipart_BinaryContentTypePart(t *testing.T) {
	// Bypass vector: attacker sets Content-Type: image/png on a multipart
	// part whose body is actually a plaintext secret. The binary-type check
	// must NOT skip scanning the part body.
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	secret := fakeAnthropicKey()
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"avatar.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		secret + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match: secret in part body with spoofed image/png Content-Type")
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected non-empty DLP matches for binary content-type bypass")
	}
}

func TestExtractMultipart_CustomPartHeaders(t *testing.T) {
	// Bypass vector: attacker puts a secret in a custom part header
	// (X-Secret) that is never extracted for DLP scanning.
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	secret := fakeAnthropicKey()
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"\r\n" +
		"X-Secret: " + secret + "\r\n\r\n" +
		"clean body content\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match: secret in custom multipart part header X-Secret")
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected non-empty DLP matches for custom part header bypass")
	}
}

func TestExtractMultipart_StructuralHeaderParams(t *testing.T) {
	// Bypass vector: attacker hides a secret in a non-standard parameter of
	// a structural MIME header (Content-Disposition or Content-Type). The
	// scanner must parse parameter values from these headers, not skip them.
	cfg := testScannerConfig()
	sc := scanner.New(cfg)

	secret := fakeAnthropicKey()
	body := "--BOUNDARY\r\n" +
		"Content-Disposition: form-data; name=\"legit\"; x-secret=\"" + secret + "\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\nhello\r\n" +
		"--BOUNDARY--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=BOUNDARY",
		MaxBytes:    1 << 20,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match for secret in Content-Disposition parameter")
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected non-empty DLP matches for structural header param bypass")
	}
}

func TestExtractMultipart_Base64TransferEncoding(t *testing.T) {
	// Bypass vector: attacker sends Content-Transfer-Encoding: base64 with
	// RFC 2045 line-wrapped base64. Go's multipart.Reader does NOT decode
	// CTE, so the scanner sees raw base64 instead of the secret.
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	secret := fakeAnthropicKey()

	// Encode the secret as base64 with MIME line wrapping (76-char lines + CRLF).
	encoded := base64Encode76(secret)

	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"data\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		encoded + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match: base64-encoded secret with Content-Transfer-Encoding header")
	}
	if len(result.DLPMatches) == 0 {
		t.Fatal("expected non-empty DLP matches for base64 transfer encoding bypass")
	}
}

// base64Encode76 encodes data as base64 with RFC 2045 line wrapping
// (76-character lines separated by CRLF), mimicking real MIME encoding.
func base64Encode76(data string) string {
	raw := base64.StdEncoding.EncodeToString([]byte(data))
	var sb strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		sb.WriteString(raw[i:end])
		if end < len(raw) {
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

// TestExtractMultipart_QuotedPrintableTransferEncoding verifies that
// quoted-printable encoded secrets are decoded and caught by DLP.
func TestExtractMultipart_QuotedPrintableTransferEncoding(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	boundary := testMultipartBoundary
	// Quoted-printable encode: replace '-' with '=2D' to break the pattern.
	qpEncoded := "sk=2Dant=2Dapi03=2DXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"data\"\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
		qpEncoded + "\r\n" +
		"--" + boundary + "--\r\n"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{
		Body:        strings.NewReader(body),
		ContentType: "multipart/form-data; boundary=" + boundary,
		MaxBytes:    cfg.RequestBodyScanning.MaxBodyBytes,
		Scanner:     sc,
	})
	if result.Clean {
		t.Fatal("expected DLP match: quoted-printable encoded secret with CTE header")
	}
}

func TestIsResponseScanExempt(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		exempt []string
		want   bool
	}{
		{"exact match", "api.openai.com", []string{"api.openai.com"}, true},
		{"no match", "evil.com", []string{"api.openai.com"}, false},
		{"wildcard match", "api.anthropic.com", []string{"*.anthropic.com"}, true},
		{"wildcard apex match", "anthropic.com", []string{"*.anthropic.com"}, true},
		{"empty list", "api.openai.com", nil, false},
		{"case insensitive", "API.OpenAI.COM", []string{"api.openai.com"}, true},
		{"multiple patterns", "api.anthropic.com", []string{"api.openai.com", "*.anthropic.com"}, true},
		{"no partial match", "notapi.openai.com", []string{"api.openai.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isResponseScanExempt(tt.host, tt.exempt); got != tt.want {
				t.Errorf("isResponseScanExempt(%q, %v) = %v, want %v", tt.host, tt.exempt, got, tt.want)
			}
		})
	}
}
