// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	// maxMultipartParts caps the number of multipart form parts parsed.
	// 100 is well above typical form submissions (usually <20 fields) while
	// bounding memory to at most 100 * maxBodyBytes of buffered part data.
	maxMultipartParts = 100

	// maxFilenameBytes caps multipart part filenames to prevent secret
	// exfiltration via long filenames. 256 bytes covers any legitimate
	// filename while blocking multi-KB exfil payloads.
	maxFilenameBytes = 256

	// scannerLabelAddressProtection is the scanner label for address poisoning
	// findings in logs and metrics, distinguishing from body_dlp (secret exfil).
	scannerLabelAddressProtection = "address_protection"
)

// BodyScanResult describes the outcome of scanning a request body or headers.
type BodyScanResult struct {
	Clean           bool
	Action          string
	DLPMatches      []scanner.TextDLPMatch
	AddressFindings []addressprotect.Finding // crypto address poisoning findings
	HeaderName      string                   // set when a header triggered the match
	Reason          string                   // human-readable block reason
}

// scanRequestBody reads, buffers, and DLP-scans an HTTP request body.
// Returns the buffered body bytes (for re-wrapping) and the scan result.
// Fail-closed: oversized bodies and compressed bodies are always blocked.
func scanRequestBody(ctx context.Context, body io.Reader, contentType, contentEncoding string, maxBytes int, sc *scanner.Scanner, agentID string) ([]byte, BodyScanResult) {
	// Content-Encoding check: compressed bodies evade DLP regex matching.
	// Parse as comma-separated tokens (RFC 7231 section 3.1.2.2).
	if hasNonIdentityEncoding(contentEncoding) {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("request body uses Content-Encoding %q; compressed bodies cannot be scanned for secrets", contentEncoding),
		}
	}

	// Read body with +1 byte to detect overflow.
	buf, err := io.ReadAll(io.LimitReader(body, int64(maxBytes)+1))
	if err != nil {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("error reading request body: %v", err),
		}
	}

	// Overflow: fail-closed block regardless of configured action.
	if len(buf) > maxBytes {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("request body exceeds max_body_bytes (%d)", maxBytes),
		}
	}

	// Empty body: clean.
	if len(buf) == 0 {
		return buf, BodyScanResult{Clean: true}
	}

	// Extract text strings from body based on content type.
	texts, parseErr := extractBodyText(buf, contentType, maxBytes)
	if parseErr != "" {
		// Multipart limit exceeded: fail-closed block.
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: parseErr,
		}
	}

	if len(texts) == 0 {
		return buf, BodyScanResult{Clean: true}
	}

	// Scan each extracted string individually (catches per-field encoded secrets).
	for _, text := range texts {
		result := sc.ScanTextForDLP(ctx, text)
		if !result.Clean {
			return buf, BodyScanResult{
				Clean:      false,
				DLPMatches: result.Matches,
			}
		}
	}

	// Joined scan: catches secrets split across multiple fields.
	// Sort to ensure deterministic ordering (Go map iteration is random).
	sorted := make([]string, len(texts))
	copy(sorted, texts)
	sort.Strings(sorted)
	joined := strings.Join(sorted, "\n")
	result := sc.ScanTextForDLP(ctx, joined)
	if !result.Clean {
		return buf, BodyScanResult{
			Clean:      false,
			DLPMatches: result.Matches,
		}
	}

	// Address poisoning detection alongside DLP.
	// Note: body address findings are currently emitted/counted as body_dlp
	// by callers (forward.go, intercept.go). Dedicated address_protection
	// log/metric path deferred to v2.
	if checker := sc.AddressChecker(); checker != nil {
		addrResult := checker.CheckText(joined, agentID)
		if len(addrResult.Findings) > 0 {
			return buf, BodyScanResult{
				Clean:           false,
				Action:          addressprotect.StrictestAction(addrResult.Findings),
				AddressFindings: addrResult.Findings,
				Reason:          fmt.Sprintf("address poisoning detected: %s", addrResult.Findings[0].Explanation),
			}
		}
	}

	return buf, BodyScanResult{Clean: true}
}

// hasNonIdentityEncoding returns true if the Content-Encoding header contains
// any encoding other than "identity" (which means no encoding).
func hasNonIdentityEncoding(ce string) bool {
	if ce == "" {
		return false
	}
	for _, enc := range strings.Split(ce, ",") {
		enc = strings.TrimSpace(strings.ToLower(enc))
		if enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}

// extractBodyText dispatches body text extraction by content type.
// Returns extracted strings and an error string if parsing limits are exceeded
// (multipart only). Empty error means success.
func extractBodyText(body []byte, contentType string, maxBytes int) ([]string, string) {
	mediaType, params, _ := mime.ParseMediaType(contentType)

	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		if !json.Valid(body) {
			return nil, "invalid JSON body"
		}
		return extract.AllStringsFromJSON(json.RawMessage(body)), ""

	case mediaType == "application/x-www-form-urlencoded":
		return extractFormURLEncoded(body)

	case mediaType == "multipart/form-data":
		if params["boundary"] == "" {
			return nil, "multipart/form-data missing boundary"
		}
		return extractMultipart(body, params["boundary"], maxBytes)

	case strings.HasPrefix(mediaType, "text/") || strings.HasSuffix(mediaType, "+xml"):
		return []string{string(body)}, ""

	default:
		// Fallback: raw text scan. Never skip unknown content types.
		// An attacker can set Content-Type: application/octet-stream on a
		// JSON body containing secrets. Raw scan catches plaintext patterns.
		return []string{string(body)}, ""
	}
}

// extractFormURLEncoded parses application/x-www-form-urlencoded bodies
// and extracts both keys and values. Returns an error string on parse failure
// (fail-closed: caller blocks).
func extractFormURLEncoded(body []byte) ([]string, string) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, "invalid application/x-www-form-urlencoded body"
	}
	var result []string
	for k, vv := range values {
		result = append(result, k)
		result = append(result, vv...)
	}
	return result, ""
}

// extractMultipart parses multipart/form-data bodies with hard limits.
// Returns extracted strings and an error message if any limit is exceeded.
// On limit violation: fail-closed (returns error, caller blocks).
func extractMultipart(body []byte, boundary string, maxBytes int) ([]string, string) {
	reader := multipart.NewReader(strings.NewReader(string(body)), boundary)

	var result []string
	partCount := 0

	for {
		if partCount >= maxMultipartParts {
			return nil, fmt.Sprintf("multipart body exceeds %d parts limit", maxMultipartParts)
		}

		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Parse error in multipart: fail-closed block.
			return nil, fmt.Sprintf("multipart parse error: %v", err)
		}
		partCount++

		// Extract metadata before closing the part.
		formName := part.FormName()
		filename := part.FileName()
		if len(filename) > maxFilenameBytes {
			return nil, fmt.Sprintf("multipart filename exceeds %d bytes", maxFilenameBytes)
		}

		// Determine if this part is binary by checking its Content-Type.
		// Binary part bodies are skipped (genuine file uploads), but metadata
		// (formName, filename) is still scanned — an attacker can exfiltrate
		// secrets via binary part filenames without the body being read.
		partContentType := part.Header.Get("Content-Type")
		if isBinaryContentType(partContentType) {
			_ = part.Close()
			// Still scan metadata from binary parts.
			if formName != "" {
				result = append(result, formName)
			}
			if filename != "" {
				result = append(result, filename)
			}
			continue
		}

		// Read part body with size limit.
		partBody, readErr := io.ReadAll(io.LimitReader(part, int64(maxBytes)+1))
		_ = part.Close()

		if readErr != nil {
			return nil, fmt.Sprintf("error reading multipart part: %v", readErr)
		}
		if len(partBody) > maxBytes {
			return nil, fmt.Sprintf("multipart part exceeds max_body_bytes (%d)", maxBytes)
		}

		if len(partBody) > 0 {
			result = append(result, string(partBody))
		}

		// Include field name and filename in extracted text (can carry exfil data).
		if formName != "" {
			result = append(result, formName)
		}
		if filename != "" {
			result = append(result, filename)
		}
	}

	return result, ""
}

// isBinaryContentType returns true for content types that are clearly binary
// (images, audio, video, application/octet-stream). Text-like types pass through
// for scanning.
func isBinaryContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(ct)
	switch {
	case strings.HasPrefix(mediaType, "image/"):
		return true
	case strings.HasPrefix(mediaType, "audio/"):
		return true
	case strings.HasPrefix(mediaType, "video/"):
		return true
	case mediaType == "application/octet-stream":
		// Don't skip: fallback raw scan catches plaintext secrets.
		return false
	default:
		return false
	}
}

// headerNameNoisyPrefixes are header name prefixes excluded from name scanning
// in "all" mode to avoid false positives. These carry browser/proxy metadata,
// not credential data.
var headerNameNoisyPrefixes = []string{
	"Sec-",
	"X-Forwarded-",
	"Traceparent",
	"Tracestate",
	"X-Request-Id",
	"X-Trace-Id",
	"X-Correlation-Id",
	"X-Amzn-Trace-Id",
}

// isNoisyHeaderName returns true if the header name matches a noisy prefix
// that should be excluded from header name DLP scanning.
func isNoisyHeaderName(name string) bool {
	canonical := http.CanonicalHeaderKey(name)
	for _, prefix := range headerNameNoisyPrefixes {
		if strings.HasPrefix(canonical, prefix) {
			return true
		}
	}
	return false
}

// scanRequestHeaders scans HTTP request headers for DLP patterns.
// Two modes: "sensitive" scans only listed headers; "all" scans everything
// except the ignore list. Headers are scanned regardless of destination
// (no allowlist skip) because agents can exfiltrate secrets in auth headers
// to any host.
func scanRequestHeaders(ctx context.Context, headers http.Header, cfg *config.Config, sc *scanner.Scanner) *BodyScanResult {
	bodyCfg := cfg.RequestBodyScanning

	// Build the set of headers to scan based on mode.
	var headersToScan map[string][]string

	switch bodyCfg.HeaderMode {
	case config.HeaderModeAll:
		// Scan all headers except those in the ignore list.
		ignoreSet := make(map[string]struct{}, len(bodyCfg.IgnoreHeaders))
		for _, h := range bodyCfg.IgnoreHeaders {
			ignoreSet[http.CanonicalHeaderKey(h)] = struct{}{}
		}
		headersToScan = make(map[string][]string)
		for name, values := range headers {
			canonical := http.CanonicalHeaderKey(name)
			if _, ignored := ignoreSet[canonical]; ignored {
				continue
			}
			headersToScan[canonical] = values
		}
	default: // sensitive
		// Scan only headers in the sensitive list.
		sensitiveSet := make(map[string]struct{}, len(bodyCfg.SensitiveHeaders))
		for _, h := range bodyCfg.SensitiveHeaders {
			sensitiveSet[http.CanonicalHeaderKey(h)] = struct{}{}
		}
		headersToScan = make(map[string][]string)
		for name, values := range headers {
			canonical := http.CanonicalHeaderKey(name)
			if _, sensitive := sensitiveSet[canonical]; sensitive {
				headersToScan[canonical] = values
			}
		}
	}

	// Per-value scanning: catches per-header encoded secrets.
	var allValues []string
	for name, values := range headersToScan {
		// In "all" mode, scan header names too (catches exfil via custom
		// header names like X-AKIA1234). No noisy prefix skip: agents
		// (unlike browsers) control all header names, including Sec-*.
		if bodyCfg.HeaderMode == config.HeaderModeAll {
			result := sc.ScanTextForDLP(ctx, name)
			if !result.Clean {
				return &BodyScanResult{
					Clean:      false,
					DLPMatches: result.Matches,
					HeaderName: name,
				}
			}
			// Include header name in joined scan to catch secrets split
			// across the name:value boundary (e.g., X-AKIA1234: EXAMPLE).
			allValues = append(allValues, name)
		}

		for _, v := range values {
			allValues = append(allValues, v)
			result := sc.ScanTextForDLP(ctx, v)
			if !result.Clean {
				return &BodyScanResult{
					Clean:      false,
					DLPMatches: result.Matches,
					HeaderName: name,
				}
			}
			// In "all" mode, scan name+value concatenation to catch secrets
			// split across the header name:value boundary.
			if bodyCfg.HeaderMode == config.HeaderModeAll {
				combined := name + v
				combinedResult := sc.ScanTextForDLP(ctx, combined)
				if !combinedResult.Clean {
					return &BodyScanResult{
						Clean:      false,
						DLPMatches: combinedResult.Matches,
						HeaderName: name,
					}
				}
			}
		}
	}

	// Joined scan: catches split-secret attacks across multiple headers
	// or repeated values of the same header.
	// Sort to ensure deterministic ordering (Go map iteration is random).
	if len(allValues) > 1 {
		sort.Strings(allValues)
		joined := strings.Join(allValues, "\n")
		result := sc.ScanTextForDLP(ctx, joined)
		if !result.Clean {
			return &BodyScanResult{
				Clean:      false,
				DLPMatches: result.Matches,
				HeaderName: "(joined)",
			}
		}
	}

	return nil
}

// evalHeaderDLP scans request headers, logs matches, and records metrics.
// Returns true if the request should be blocked (match found, action=block,
// enforce enabled). The caller handles the response format (http.Error vs
// writeJSON) since it differs between forward proxy and fetch handler.
func (p *Proxy) evalHeaderDLP(ctx context.Context, headers http.Header, cfg *config.Config, sc *scanner.Scanner,
	logger *audit.Logger, method, url, hostname, clientIP, requestID, agent string, start time.Time,
) bool {
	if !cfg.RequestBodyScanning.Enabled || !cfg.RequestBodyScanning.ScanHeaders {
		return false
	}
	headerResult := scanRequestHeaders(ctx, headers, cfg, sc)
	if headerResult == nil {
		return false
	}
	action := cfg.RequestBodyScanning.Action
	patternNames := dlpMatchNames(headerResult.DLPMatches)

	logger.LogHeaderDLP(method, url, headerResult.HeaderName, action, clientIP, requestID, "", patternNames)
	p.metrics.RecordHeaderDLP(action, agent)

	if action == config.ActionBlock && cfg.EnforceEnabled() {
		p.metrics.RecordBlocked(hostname, "header_dlp", time.Since(start), agent)
		return true
	}
	return false
}
