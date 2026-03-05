package proxy

import (
	"context"
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected DLP match in JSON key")
	}
}

func TestScanRequestBody_FormURLEncoded(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := "secret=" + fakeAPIKey() + "&name=test"
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/x-www-form-urlencoded", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected DLP match in form body")
	}
}

func TestScanRequestBody_PlainText(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := "my secret key is " + fakeAPIKey()
	_, result := scanRequestBody(
		strings.NewReader(body),
		"text/plain", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/octet-stream", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"image/png", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected DLP match via fallback raw scan on image/png")
	}
}

func TestScanRequestBody_CompressedGzip(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(
		strings.NewReader("compressed data"),
		"application/json", "gzip", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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

	_, result := scanRequestBody(
		strings.NewReader("compressed data"),
		"application/json", "deflate", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected fail-closed block on deflate")
	}
}

func TestScanRequestBody_CompressedCaseMismatch(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(
		strings.NewReader("data"),
		"application/json", "GZip", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected fail-closed block on case-insensitive gzip")
	}
}

func TestScanRequestBody_CompressedCommaSeparated(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(
		strings.NewReader("data"),
		"application/json", "gzip, identity", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected fail-closed block on comma-separated with gzip")
	}
}

func TestScanRequestBody_IdentityEncodingAllowed(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	_, result := scanRequestBody(
		strings.NewReader("clean body text"),
		"text/plain", "identity", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if !result.Clean {
		t.Fatal("identity encoding should be allowed")
	}
}

func TestScanRequestBody_EmptyBody(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	buf, result := scanRequestBody(
		strings.NewReader(""),
		"application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"text/plain", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected DLP match from joined scan of split secret")
	}
}

func TestScanRequestBody_CleanJSON(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	body := `{"name": "test", "value": 42}`
	buf, result := scanRequestBody(
		strings.NewReader(body),
		"application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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
	_, result := scanRequestBody(
		strings.NewReader(body),
		"application/xml", "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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

	_, result := scanRequestBody(
		strings.NewReader(body),
		"multipart/form-data; boundary="+boundary, "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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

	_, result := scanRequestBody(
		strings.NewReader(body),
		"multipart/form-data; boundary="+boundary, "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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

	_, result := scanRequestBody(
		strings.NewReader(body),
		"multipart/form-data; boundary="+boundary, "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
	if result != nil {
		t.Fatal("hop-by-hop header should be ignored in all mode")
	}
}

func TestScanRequestHeaders_EmptyHeaders(t *testing.T) {
	cfg := testScannerConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	result := scanRequestHeaders(http.Header{}, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
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

	result := scanRequestHeaders(headers, cfg, sc)
	if result == nil || result.Clean {
		t.Fatal("expected DLP match for secret in Authorization header (allowlist must not bypass header DLP)")
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

	buf, result := scanRequestBody(reader, "application/json", "", cfg.RequestBodyScanning.MaxBodyBytes, sc)
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
	p := New(cfg, logger, sc, m)

	// Create a request to the fetch handler with a secret in the header.
	req := httptest.NewRequest(http.MethodGet, "/fetch?url="+upstream.URL, nil)
	req.Header.Set("Authorization", "Bearer "+fakeAPIKey())
	w := httptest.NewRecorder()

	p.handleFetch(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from fetch handler for header with secret, got %d", w.Code)
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

	_, result := scanRequestBody(
		strings.NewReader(sb.String()),
		"multipart/form-data; boundary="+boundary, "", cfg.RequestBodyScanning.MaxBodyBytes, sc,
	)
	if result.Clean {
		t.Fatal("expected fail-closed block when multipart part limit exceeded")
	}
	if result.Action != config.ActionBlock {
		t.Fatalf("expected block action, got %q", result.Action)
	}
}
