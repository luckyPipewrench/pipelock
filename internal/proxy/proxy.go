// Package proxy implements the Pipelock fetch proxy HTTP server.
// The fetch proxy runs in an unprivileged zone with NO access to secrets.
// It receives URL requests from the agent, scans them, fetches content,
// and returns extracted text.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	readability "github.com/go-shiori/go-readability"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// contextKey is used for storing per-request values in context.
type contextKey int

const (
	ctxKeyClientIP  contextKey = iota
	ctxKeyRequestID
)

// requestCounter provides monotonic request IDs.
var requestCounter atomic.Uint64

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

// Proxy is the Pipelock fetch proxy server.
type Proxy struct {
	config  *config.Config
	logger  *audit.Logger
	scanner *scanner.Scanner
	client  *http.Client
	server  *http.Server
}

// FetchResponse is the JSON response returned by the /fetch endpoint.
type FetchResponse struct {
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Content     string `json:"content,omitempty"`
	Error       string `json:"error,omitempty"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"block_reason,omitempty"`
}

// New creates a new fetch proxy from config.
func New(cfg *config.Config, logger *audit.Logger, sc *scanner.Scanner) *Proxy {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.FetchProxy.TimeoutSeconds) * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	p := &Proxy{
		config:  cfg,
		logger:  logger,
		scanner: sc,
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.FetchProxy.TimeoutSeconds) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects (max 5)")
				}
				originalURL := via[0].URL.String()
				redirectURL := req.URL.String()
				clientIP, _ := req.Context().Value(ctxKeyClientIP).(string)
				requestID, _ := req.Context().Value(ctxKeyRequestID).(string)
				logger.LogRedirect(originalURL, redirectURL, clientIP, requestID, len(via))
				// Scan each redirect URL through the scanner
				result := sc.Scan(redirectURL)
				if !result.Allowed {
					if cfg.EnforceEnabled() {
						logger.LogBlocked("GET", redirectURL, "redirect", fmt.Sprintf("redirect from %s blocked: %s", originalURL, result.Reason), clientIP, requestID)
						return fmt.Errorf("redirect blocked: %s", result.Reason)
					}
					logger.LogAnomaly("GET", redirectURL, fmt.Sprintf("[audit] redirect from %s: %s", originalURL, result.Reason), clientIP, requestID, result.Score)
				}
				return nil
			},
		},
	}
	return p
}

// Start starts the fetch proxy HTTP server. It blocks until the context
// is cancelled or the server encounters a fatal error.
func (p *Proxy) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/health", p.handleHealth)

	p.server = &http.Server{
		Addr:    p.config.FetchProxy.Listen,
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: time.Duration(p.config.FetchProxy.TimeoutSeconds+10) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	// The done channel ensures this goroutine exits if ListenAndServe
	// fails immediately (e.g., address already in use).
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.server.Shutdown(shutdownCtx); err != nil {
				p.logger.LogError("SHUTDOWN", p.config.FetchProxy.Listen, "", "", err)
			}
		case <-done:
		}
	}()

	p.logger.LogStartup(p.config.FetchProxy.Listen, p.config.Mode)

	err := p.server.ListenAndServe()
	close(done) // unblock shutdown goroutine if server failed immediately
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleFetch processes URL fetch requests.
func (p *Proxy) handleFetch(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	requestID := fmt.Sprintf("req-%d", requestCounter.Add(1))

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, FetchResponse{
			Error:   "only GET allowed",
			Blocked: false,
		})
		return
	}

	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		writeJSON(w, http.StatusBadRequest, FetchResponse{
			Error:   "missing 'url' query parameter",
			Blocked: false,
		})
		return
	}

	// Parse and validate URL scheme
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		writeJSON(w, http.StatusBadRequest, FetchResponse{
			URL:     targetURL,
			Error:   "invalid URL: must be http or https",
			Blocked: false,
		})
		return
	}

	// Scan URL through all scanners
	result := p.scanner.Scan(targetURL)
	if !result.Allowed {
		if p.config.EnforceEnabled() {
			p.logger.LogBlocked("GET", targetURL, result.Scanner, result.Reason, clientIP, requestID)
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL:         targetURL,
				Blocked:     true,
				BlockReason: result.Reason,
			})
			return
		}
		// Audit mode: log anomaly but allow through
		p.logger.LogAnomaly("GET", targetURL, fmt.Sprintf("[audit] %s: %s", result.Scanner, result.Reason), clientIP, requestID, result.Score)
	}

	// Record successful scan for rate limiting
	p.scanner.RecordRequest(strings.ToLower(parsed.Hostname()))

	// Fetch the URL — attach clientIP/requestID to context for redirect logging
	ctx := context.WithValue(r.Context(), ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		p.logger.LogError("GET", targetURL, clientIP, requestID, err)
		writeJSON(w, http.StatusInternalServerError, FetchResponse{
			URL:   targetURL,
			Error: fmt.Sprintf("creating request: %v", err),
		})
		return
	}

	req.Header.Set("User-Agent", p.config.FetchProxy.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain,*/*;q=0.8")

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.LogError("GET", targetURL, clientIP, requestID, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   targetURL,
			Error: fmt.Sprintf("fetch failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	// Limit response body size
	maxBytes := int64(p.config.FetchProxy.MaxResponseMB) * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		p.logger.LogError("GET", targetURL, clientIP, requestID, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   targetURL,
			Error: fmt.Sprintf("reading response: %v", err),
		})
		return
	}

	contentType := resp.Header.Get("Content-Type")
	content := string(body)
	title := ""

	// Use go-readability for HTML content extraction
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
		article, err := readability.FromReader(strings.NewReader(content), parsed)
		if err != nil {
			p.logger.LogAnomaly("GET", targetURL, fmt.Sprintf("readability extraction failed: %v", err), clientIP, requestID, 0.3)
		} else if article.TextContent != "" {
			title = article.Title
			content = article.TextContent
		}
	}

	// Response scanning: check fetched content for prompt injection
	if p.scanner.ResponseScanningEnabled() {
		scanResult := p.scanner.ScanResponse(content)
		if !scanResult.Clean {
			patternNames := make([]string, len(scanResult.Matches))
			for i, m := range scanResult.Matches {
				patternNames[i] = m.PatternName
			}
			switch p.scanner.ResponseAction() {
			case "block":
				reason := fmt.Sprintf("response contains prompt injection: %s", strings.Join(patternNames, ", "))
				p.logger.LogBlocked("GET", targetURL, "response_scan", reason, clientIP, requestID)
				writeJSON(w, http.StatusForbidden, FetchResponse{URL: targetURL, Blocked: true, BlockReason: reason})
				return
			case "strip":
				content = scanResult.TransformedContent
				p.logger.LogResponseScan(targetURL, clientIP, requestID, "strip", len(scanResult.Matches), patternNames)
			case "warn":
				p.logger.LogResponseScan(targetURL, clientIP, requestID, "warn", len(scanResult.Matches), patternNames)
			}
		}
	}

	duration := time.Since(start)
	p.logger.LogAllowed("GET", targetURL, clientIP, requestID, resp.StatusCode, len(body), duration)

	writeJSON(w, http.StatusOK, FetchResponse{
		URL:         targetURL,
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
		Title:       title,
		Content:     content,
		Blocked:     false,
	})
}

// handleHealth returns proxy health status.
func (p *Proxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"version": Version,
		"mode":    p.config.Mode,
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Best effort: header already sent, log to stderr
		fmt.Fprintf(os.Stderr, "pipelock: writeJSON encode error: %v\n", err)
	}
}
