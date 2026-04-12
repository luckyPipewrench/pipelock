// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/textproto"
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

	// scannerLabelBodyDLP is the scanner label for DLP pattern findings in
	// request bodies (secret exfiltration detection).
	scannerLabelBodyDLP = "body_dlp"

	// scannerLabelAddressProtection is the scanner label for address poisoning
	// findings in logs and metrics, distinguishing from body_dlp (secret exfil).
	scannerLabelAddressProtection = "address_protection"
)

// isDomainExempt checks if a hostname matches any pattern in a domain
// exemption list. Uses scanner.MatchDomain for consistent wildcard
// semantics: *.discord.com matches both sub.discord.com AND discord.com
// itself, matching the behavior of api_allowlist and CEE exempt_domains
// throughout the product.
func isDomainExempt(hostname string, exemptDomains []string) bool {
	for _, pattern := range exemptDomains {
		if scanner.MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}

// isAdaptiveExempt checks if a hostname matches the adaptive enforcement
// exempt_domains list.
func isAdaptiveExempt(hostname string, exemptDomains []string) bool {
	return isDomainExempt(hostname, exemptDomains)
}

// isResponseScanExempt checks if a hostname matches the response scanning
// exempt_domains list. Responses from exempt domains skip injection scanning
// (DLP on the outbound request still applies).
func isResponseScanExempt(hostname string, exemptDomains []string) bool {
	return isDomainExempt(hostname, exemptDomains)
}

// BodyScanResult describes the outcome of scanning a request body or headers.
type BodyScanResult struct {
	Clean           bool
	Action          string
	DLPMatches      []scanner.TextDLPMatch
	AddressFindings []addressprotect.Finding // crypto address poisoning findings
	HeaderName      string                   // set when a header triggered the match
	Reason          string                   // human-readable block reason
}

// BodyScanRequest groups the parameters for scanRequestBody, keeping the
// function signature under the 6-parameter guideline (ctx is passed separately).
type BodyScanRequest struct {
	Body            io.Reader
	ContentType     string
	ContentEncoding string
	MaxBytes        int
	Scanner         *scanner.Scanner
	AgentID         string
}

// scanRequestBody reads, buffers, and DLP-scans an HTTP request body.
// Returns the buffered body bytes (for re-wrapping) and the scan result.
// Fail-closed: oversized bodies and compressed bodies are always blocked.
func scanRequestBody(ctx context.Context, req BodyScanRequest) ([]byte, BodyScanResult) {
	// Content-Encoding check: compressed bodies evade DLP regex matching.
	// Parse as comma-separated tokens (RFC 7231 section 3.1.2.2).
	if hasNonIdentityEncoding(req.ContentEncoding) {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("request body uses Content-Encoding %q; compressed bodies cannot be scanned for secrets", req.ContentEncoding),
		}
	}

	// Read body with +1 byte to detect overflow.
	buf, err := io.ReadAll(io.LimitReader(req.Body, int64(req.MaxBytes)+1))
	if err != nil {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("error reading request body: %v", err),
		}
	}

	// Overflow: fail-closed block regardless of configured action.
	if len(buf) > req.MaxBytes {
		return nil, BodyScanResult{
			Clean:  false,
			Action: config.ActionBlock,
			Reason: fmt.Sprintf("request body exceeds max_body_bytes (%d)", req.MaxBytes),
		}
	}

	// Empty body: clean.
	if len(buf) == 0 {
		return buf, BodyScanResult{Clean: true}
	}

	// Extract text strings from body based on content type.
	texts, parseErr := extractBodyText(buf, req.ContentType, req.MaxBytes)
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
		result := req.Scanner.ScanTextForDLP(ctx, text)
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
	result := req.Scanner.ScanTextForDLP(ctx, joined)
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
	if checker := req.Scanner.AddressChecker(); checker != nil {
		addrResult := checker.CheckText(joined, req.AgentID)
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

		// Scan ALL part headers for secret exfiltration.
		// Custom headers (X-Secret, etc.) are scanned as raw values.
		// Structural headers (Content-Type, Content-Disposition) are parsed
		// for parameter values — an attacker can hide secrets in non-standard
		// params like Content-Disposition: form-data; x-data="<credential>".
		for name, values := range part.Header {
			canonical := textproto.CanonicalMIMEHeaderKey(name)
			if canonical == "Content-Type" || canonical == "Content-Disposition" {
				// Parse parameter values from structural headers.
				// On parse failure, fall back to scanning raw value
				// so malformed headers don't bypass inspection.
				for _, v := range values {
					_, params, parseErr := mime.ParseMediaType(v)
					if parseErr != nil {
						result = append(result, v)
						continue
					}
					for _, pv := range params {
						result = append(result, pv)
					}
				}
				continue
			}
			if canonical == "Content-Transfer-Encoding" {
				continue // Pure token (base64/7bit), no params, no exfil surface.
			}
			result = append(result, values...)
		}

		// Read ALL part bodies regardless of Content-Type. An attacker can
		// set Content-Type: image/png on a part whose body is plaintext
		// containing secrets. Real binary data (actual images) won't match
		// DLP patterns (they're structured key prefixes like sk-ant-, AKIA).
		partBody, readErr := io.ReadAll(io.LimitReader(part, int64(maxBytes)+1))
		_ = part.Close()

		if readErr != nil {
			return nil, fmt.Sprintf("error reading multipart part: %v", readErr)
		}
		if len(partBody) > maxBytes {
			return nil, fmt.Sprintf("multipart part exceeds max_body_bytes (%d)", maxBytes)
		}

		// Decode Content-Transfer-Encoding before scanning. Go's
		// multipart.Reader does NOT decode CTE, so base64/QP content
		// reaches the scanner as raw encoded text. Decode it so DLP
		// patterns match the actual secret. If decoding fails, scan raw
		// (fail-closed: don't skip, raw scan still catches plaintext).
		cte := strings.ToLower(part.Header.Get("Content-Transfer-Encoding"))
		rawBody := string(partBody)
		switch cte {
		case "base64":
			// Strip ALL ASCII whitespace (RFC 2045 allows 76-char lines + CRLF,
			// but real-world MIME may include tabs/spaces).
			cleaned := strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, rawBody)
			decoded, err := base64.StdEncoding.DecodeString(cleaned)
			if err == nil {
				// Scan BOTH decoded (catches actual secrets) and raw
				// (catches patterns visible in encoded form).
				result = append(result, string(decoded))
			}
			// Always scan raw form too — fail-closed on decode failure,
			// and catches patterns visible in encoded form.
			result = append(result, rawBody)
		case "quoted-printable":
			decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(partBody)))
			if err == nil {
				result = append(result, string(decoded))
			}
			result = append(result, rawBody)
		default:
			if len(partBody) > 0 {
				result = append(result, rawBody)
			}
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
// Returns (blocked, hadFinding): blocked is true if the request must be
// blocked (match found, action=block, enforce enabled); hadFinding is true
// whenever a DLP match was detected, even in audit/warn mode. The caller
// handles the response format (http.Error vs writeJSON) since it differs
// between forward proxy and fetch handler.
func (p *Proxy) evalHeaderDLP(ctx context.Context, headers http.Header, cfg *config.Config, sc *scanner.Scanner,
	logger *audit.Logger, actx audit.LogContext, hostname string, start time.Time,
) (blocked bool, hadFinding bool) {
	if !cfg.RequestBodyScanning.Enabled || !cfg.RequestBodyScanning.ScanHeaders {
		return false, false
	}
	headerResult := scanRequestHeaders(ctx, headers, cfg, sc)
	if headerResult == nil {
		return false, false
	}
	action := cfg.RequestBodyScanning.Action
	patternNames := dlpMatchNames(headerResult.DLPMatches)
	bundleRules := dlpBundleRules(headerResult.DLPMatches)

	logger.LogHeaderDLP(actx, headerResult.HeaderName, action, patternNames, bundleRules)
	p.metrics.RecordHeaderDLP(action, actx.Agent())

	if action == config.ActionBlock && cfg.EnforceEnabled() {
		p.metrics.RecordBlocked(hostname, "header_dlp", time.Since(start), actx.Agent())
		return true, true
	}
	return false, true
}
