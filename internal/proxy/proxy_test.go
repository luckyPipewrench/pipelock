package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func setupTestProxy(t *testing.T) (*Proxy, *httptest.Server) {
	t.Helper()

	// Create a test backend that returns HTML content
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Test Page</title></head><body><p>Hello world</p></body></html>`)
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"message":"hello"}`)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "Hello world")
		case "/slow":
			time.Sleep(5 * time.Second)
			fmt.Fprint(w, "too slow")
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
		}
	}))

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 5
	// Disable SSRF check for test backend (which is on 127.0.0.1)
	cfg.Internal = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc)

	return p, backend
}

func TestHealthEndpoint(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Manually call the handler
	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.handleHealth)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %s", resp["status"])
	}
}

func TestFetchEndpoint_Success(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/text", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if resp.Blocked {
		t.Error("expected not blocked")
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected status_code=200, got %d", resp.StatusCode)
	}
	if resp.Content == "" {
		t.Error("expected non-empty content")
	}
}

func TestFetchEndpoint_MissingURL(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestFetchEndpoint_InvalidScheme(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url=ftp://example.com/file", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestFetchEndpoint_BlockedDomain(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url=https://pastebin.com/raw/abc", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if !resp.Blocked {
		t.Error("expected blocked=true")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty block reason")
	}
}

func TestFetchEndpoint_PostNotAllowed(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("POST", "/fetch?url=https://example.com", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestFetchEndpoint_HTMLContent(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/html", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	// go-readability should extract text content
	if resp.Content == "" {
		t.Error("expected non-empty content from HTML")
	}
}

func TestFetchEndpoint_JSONContent(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/json", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	// JSON content should be returned as-is
	if resp.Content != `{"message":"hello"}` {
		t.Errorf("expected JSON content, got %q", resp.Content)
	}
}

func TestFetchEndpoint_DLPBlocked(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	// URL with an AWS key in the query param
	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/text?key=AKIAIOSFODNN7EXAMPLE", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for DLP-blocked URL, got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if !resp.Blocked {
		t.Error("expected blocked=true for DLP")
	}
}

func TestFetchEndpoint_NotFound(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/nonexistent", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	// Should succeed (we proxy the response, 404 is from upstream)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (proxied 404), got %d", w.Code)
	}

	var resp FetchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("expected status_code=404 from backend, got %d", resp.StatusCode)
	}
}

func TestFetchEndpoint_InvalidURL(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url=not-a-valid-url", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestFetchEndpoint_ResponseContentType(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/text", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	// The proxy response itself should always be application/json
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
}

func TestFetchEndpoint_BackendError(t *testing.T) {
	// Create a backend that immediately closes connections
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer backend.Close()

	cfg := config.Defaults()
	cfg.FetchProxy.TimeoutSeconds = 2
	cfg.Internal = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc)

	req := httptest.NewRequest("GET", "/fetch?url="+backend.URL+"/broken", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 for backend error, got %d", w.Code)
	}
}

func TestHealthEndpoint_Format(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", p.handleHealth)
	mux.ServeHTTP(w, req)

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}

	if resp["version"] == "" {
		t.Error("expected version in health response")
	}
	if resp["mode"] == "" {
		t.Error("expected mode in health response")
	}
}

func TestFetchEndpoint_HeadNotAllowed(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("HEAD", "/fetch?url=https://example.com", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for HEAD, got %d", w.Code)
	}
}

func TestFetchEndpoint_PutNotAllowed(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("PUT", "/fetch?url=https://example.com", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", w.Code)
	}
}

func TestFetchEndpoint_DeleteNotAllowed(t *testing.T) {
	p, backend := setupTestProxy(t)
	defer backend.Close()

	req := httptest.NewRequest("DELETE", "/fetch?url=https://example.com", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for DELETE, got %d", w.Code)
	}
}

func TestProxy_StartAndShutdown(t *testing.T) {
	cfg := config.Defaults()
	cfg.FetchProxy.Listen = "127.0.0.1:0" // random port
	cfg.Internal = nil

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	p := New(cfg, logger, sc)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Start(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected clean shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("proxy did not shut down within 5 seconds")
	}
}
