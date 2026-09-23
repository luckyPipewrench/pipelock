// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/binary"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/shield"
)

const (
	shieldUninspectableLayer       = "shield_uninspectable"
	shieldUTF16ScanHeadBlockReason = "Browser Shield cannot safely inspect a UTF-16 response from a scan head; correct upstream encoding or use browser_shield.exempt_domains for an intentional whole-host skip"
	browserMIMESniffHeaderBytes    = 1445
)

type shieldPipelineResult struct {
	body                []byte
	summary             *receipt.ShieldSummary
	uninspectableReason string
	utf16               bool
	pipeline            shield.PipelineType
}

type shieldUTF16Order uint8

const (
	shieldUTF16LE shieldUTF16Order = iota + 1
	shieldUTF16BE
)

var (
	xmlEncodingDeclarationRE = regexp.MustCompile(`(?is)^\s*<\?xml\s+[^>]*\bencoding\s*=\s*["']\s*([^"'\s?>]+)\s*["'][^>]*\?>`)
	charsetParameterRE       = regexp.MustCompile(`(?i)(?:^|;)\s*charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s]*))`)
)

// runShieldPipelineWithEncoding is the common byte boundary for every Browser
// Shield response transport. UTF-16 is decoded strictly before Shield sees it;
// unchanged content deliberately keeps its original bytes and metadata.
func runShieldPipelineWithEncoding(engine *shield.Engine, body []byte, contentType string, headers http.Header, cfg *config.BrowserShield, m *metrics.Metrics, transport string) shieldPipelineResult {
	pipeline := detectShieldPipelineForResponse(contentType, body, headers)
	if pipeline == shield.PipelineNone {
		return shieldPipelineResult{body: body, pipeline: pipeline}
	}

	content, utf16, err := decodeShieldUTF16(body, contentType, pipeline)
	if err != nil {
		return shieldPipelineResult{body: body, pipeline: pipeline, uninspectableReason: fmt.Sprintf("Browser Shield cannot safely inspect UTF-16 response: %v; correct upstream encoding or use browser_shield.exempt_domains for an intentional whole-host skip", err)}
	}
	if !utf16 {
		content = string(body)
	}

	headerNonce := shield.ExtractCSPNonce(headers)
	shieldResult := engine.RewriteWithNonce(content, pipeline, cfg, headerNonce)
	result := shieldPipelineResult{body: body, summary: shieldSummaryFromResult(shieldResult), utf16: utf16, pipeline: pipeline}
	if !shieldResult.Rewritten {
		return result
	}
	if utf16 && isXMLShieldPipeline(pipeline) {
		shieldResult.Content = repairXMLUTF8Declaration(shieldResult.Content)
	}
	result.body = []byte(shieldResult.Content)
	if headers != nil {
		repairShieldResponseMetadata(headers, pipeline, result.body, utf16)
	}
	recordShieldRewriteMetrics(m, shieldResult, transport)
	return result
}

func recordShieldRewriteMetrics(m *metrics.Metrics, result shield.Result, transport string) {
	if result.ExtensionHits > 0 {
		m.RecordShieldRewrite("extension", transport)
	}
	if result.TrackingHits > 0 {
		m.RecordShieldRewrite("tracking", transport)
	}
	if result.TrapHits > 0 {
		m.RecordShieldRewrite("trap", transport)
	}
	if result.ShimInjected {
		m.RecordShieldShimInjected(transport)
	}
}

// decodeShieldUTF16 only recognizes UTF-16 when a BOM, a supported charset
// declaration, or the XML/HTML UTF-16 byte signature establishes that class.
// It does not use the scanner's lossy decoder: malformed code units are a
// refusal, not replacement characters that could hide Shield evidence.
func decodeShieldUTF16(body []byte, contentType string, pipeline shield.PipelineType) (string, bool, error) {
	if hasShieldUTF8BOM(body) {
		return "", false, nil
	}
	declared, parseErr := shieldDeclaredCharset(contentType)
	bomOrder, bom := shieldUTF16BOM(body)
	signatureOrder, signature := shieldUTF16Signature(body)
	declaresUTF16 := isUTF16Charset(declared)
	if !bom && !signature && !declaresUTF16 {
		return "", false, nil
	}
	if parseErr != nil {
		return "", true, fmt.Errorf("invalid Content-Type charset declaration")
	}
	if declared != "" && !isUTF16Charset(declared) && declared != "utf-8" && declared != "utf8" {
		return "", true, fmt.Errorf("unsupported charset declaration %q", declared)
	}

	order := bomOrder
	if order == 0 {
		order = charsetUTF16Order(declared)
	}
	if order == 0 {
		order = signatureOrder
	}
	if declared == "utf-16" && signature && signatureOrder != order {
		return "", true, fmt.Errorf("UTF-16 signature and declared byte order disagree")
	}
	if order == 0 {
		return "", true, fmt.Errorf("UTF-16 byte order is ambiguous")
	}
	if bom && declared != "utf-16" && charsetUTF16Order(declared) != 0 && charsetUTF16Order(declared) != bomOrder {
		return "", true, fmt.Errorf("BOM and Content-Type charset disagree")
	}
	if declared == "utf-8" || declared == "utf8" {
		return "", true, fmt.Errorf("UTF-16 body conflicts with Content-Type charset %q", declared)
	}

	start := 0
	if bom {
		start = 2
	}
	decoded, err := strictDecodeUTF16(body[start:], order)
	if err != nil {
		return "", true, err
	}
	if declaration := embeddedCharsetDeclaration(decoded, pipeline); declaration != "" {
		if !isUTF16Charset(declaration) {
			return "", true, fmt.Errorf("unsupported or contradictory document charset %q", declaration)
		}
		if declaredOrder := charsetUTF16Order(declaration); declaration != "utf-16" && declaredOrder != 0 && declaredOrder != order {
			return "", true, fmt.Errorf("document charset and UTF-16 byte order disagree")
		}
	}
	return decoded, true, nil
}

// detectShieldPipeline keeps Browser Shield classification aligned with a
// browser when Go's MIME parser disagrees on whitespace or rejects parameters
// after a supported media type. The browser retains a valid ASCII media-type
// essence when later parameters are malformed, so recovery is independent of
// response encoding.
func detectShieldPipeline(contentType string, body []byte) shield.PipelineType {
	return detectShieldPipelineForResponse(contentType, body, nil)
}

func detectShieldPipelineForResponse(contentType string, body []byte, headers http.Header) shield.PipelineType {
	baseType, validBase := shieldMediaTypeEssence(contentType)
	if validBase {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err == nil {
			pipeline := shield.DetectPipeline(mediaType, nil)
			if pipeline != shield.PipelineNone || (mediaType != "" && !browserContentTypeIsGeneric(mediaType)) {
				return pipeline
			}
		} else {
			recovered := shield.DetectPipeline(baseType, nil)
			if recovered != shield.PipelineNone || !browserContentTypeIsGeneric(baseType) {
				return recovered
			}
		}
	}
	// Do not promote an inert nosniff response into an active HTML response.
	if responseForbidsMIMESniffing(headers) {
		return shield.PipelineNone
	}
	pipeline := shield.DetectPipeline("", shieldSniffHeader(body))
	if pipeline != shield.PipelineNone {
		return pipeline
	}
	if !validBase {
		return pipeline
	}
	return shield.DetectPipeline(baseType, nil)
}

func browserContentTypeIsGeneric(mediaType string) bool {
	switch mediaType {
	case "unknown/unknown", "application/unknown", "*/*":
		return true
	default:
		return false
	}
}

func responseForbidsMIMESniffing(headers http.Header) bool {
	values := headers.Values("X-Content-Type-Options")
	if len(values) == 0 {
		return false
	}
	first, _, _ := strings.Cut(values[0], ",")
	first = strings.Trim(first, "\t\n\r ")
	return strings.EqualFold(first, "nosniff")
}

func shieldSniffHeader(body []byte) []byte {
	header := body[:min(len(body), browserMIMESniffHeaderBytes)]
	for len(header) > 0 {
		switch header[0] {
		case '\t', '\n', '\f', '\r', ' ':
			header = header[1:]
		default:
			return header
		}
	}
	return header
}

// shieldMediaTypeEssence accepts only the ASCII token grammar and HTTP
// whitespace used by browsers. Go's MIME parser trims Unicode whitespace,
// which can turn a browser-invalid field into an authoritative active type.
func shieldMediaTypeEssence(contentType string) (string, bool) {
	baseType := contentType
	if idx := strings.IndexByte(baseType, ';'); idx >= 0 {
		baseType = baseType[:idx]
	}
	baseType = strings.TrimFunc(baseType, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	typeName, subtype, ok := strings.Cut(baseType, "/")
	if !ok || typeName == "" || subtype == "" || strings.Contains(subtype, "/") {
		return "", false
	}
	for i := 0; i < len(typeName); i++ {
		if !shieldMIMETypeTokenByte(typeName[i]) {
			return "", false
		}
	}
	for i := 0; i < len(subtype); i++ {
		if !shieldMIMETypeTokenByte(subtype[i]) {
			return "", false
		}
	}
	return strings.ToLower(baseType), true
}

func shieldMIMETypeTokenByte(b byte) bool {
	if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

// shieldDeclaredCharset returns the first charset parameter even when a later
// MIME parameter makes mime.ParseMediaType reject the field. Browsers retain
// that earlier parameter; we need it only to classify the response as UTF-16
// and fail closed. parseErr remains nonnil so the decoder never accepts a
// malformed declaration.
func shieldDeclaredCharset(contentType string) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err == nil {
		return normalizeShieldCharset(params["charset"]), nil
	}
	match := charsetParameterRE.FindStringSubmatch(contentType)
	if len(match) == 0 {
		return "", err
	}
	for _, candidate := range match[1:] {
		if candidate != "" {
			return normalizeShieldCharset(candidate), err
		}
	}
	return "", err
}

// isShieldUTF16Response classifies an oversize response without decoding it.
// Scan-head mode cannot safely inspect a partial UTF-16 character stream, so
// the caller only needs the encoding class before refusing the response.
func isShieldUTF16Response(body []byte, contentType string) bool {
	if hasShieldUTF8BOM(body) {
		return false
	}
	if _, bom := shieldUTF16BOM(body); bom {
		return true
	}
	if _, signature := shieldUTF16Signature(body); signature {
		return true
	}
	declared, _ := shieldDeclaredCharset(contentType)
	return isUTF16Charset(declared)
}

func hasShieldUTF8BOM(body []byte) bool {
	return len(body) >= 3 && body[0] == 0xef && body[1] == 0xbb && body[2] == 0xbf
}

func normalizeShieldCharset(charset string) string {
	return strings.ToLower(strings.Trim(charset, " \t\n\f\r"))
}

func shieldUTF16BOM(body []byte) (shieldUTF16Order, bool) {
	if len(body) < 2 {
		return 0, false
	}
	switch {
	case body[0] == 0xff && body[1] == 0xfe:
		return shieldUTF16LE, true
	case body[0] == 0xfe && body[1] == 0xff:
		return shieldUTF16BE, true
	default:
		return 0, false
	}
}

func shieldUTF16Signature(body []byte) (shieldUTF16Order, bool) {
	if len(body) < 2 {
		return 0, false
	}
	if body[0] == '<' && body[1] == 0 {
		return shieldUTF16LE, true
	}
	if body[0] == 0 && body[1] == '<' {
		return shieldUTF16BE, true
	}
	return 0, false
}

func isUTF16Charset(charset string) bool {
	return charsetUTF16Order(charset) != 0
}

func charsetUTF16Order(charset string) shieldUTF16Order {
	switch charset {
	case "csunicode", "iso-10646-ucs-2", "ucs-2", "unicode", "unicodefeff", "utf-16", "utf-16le":
		return shieldUTF16LE
	case "unicodefffe", "utf-16be":
		return shieldUTF16BE
	default:
		return 0
	}
}

func strictDecodeUTF16(body []byte, order shieldUTF16Order) (string, error) {
	if len(body)%2 != 0 {
		return "", fmt.Errorf("odd UTF-16 byte count")
	}
	runes := make([]rune, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		var unit uint16
		if order == shieldUTF16LE {
			unit = binary.LittleEndian.Uint16(body[i:])
		} else {
			unit = binary.BigEndian.Uint16(body[i:])
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+2 >= len(body) {
				return "", fmt.Errorf("unpaired high surrogate")
			}
			var low uint16
			if order == shieldUTF16LE {
				low = binary.LittleEndian.Uint16(body[i+2:])
			} else {
				low = binary.BigEndian.Uint16(body[i+2:])
			}
			if low < 0xdc00 || low > 0xdfff {
				return "", fmt.Errorf("high surrogate without low surrogate")
			}
			runes = append(runes, rune(0x10000+((uint32(unit)-0xd800)<<10)+(uint32(low)-0xdc00)))
			i += 2
		case unit >= 0xdc00 && unit <= 0xdfff:
			return "", fmt.Errorf("unpaired low surrogate")
		default:
			runes = append(runes, rune(unit))
		}
	}
	return string(runes), nil
}

func embeddedCharsetDeclaration(body string, pipeline shield.PipelineType) string {
	if isXMLShieldPipeline(pipeline) {
		if match := xmlEncodingDeclarationRE.FindStringSubmatch(body); len(match) == 2 {
			return strings.ToLower(match[1])
		}
		return ""
	}
	return ""
}

func isXMLShieldPipeline(pipeline shield.PipelineType) bool {
	return pipeline == shield.PipelineSVG || pipeline == shield.PipelineXHTML
}

func repairXMLUTF8Declaration(body string) string {
	return xmlEncodingDeclarationRE.ReplaceAllStringFunc(body, func(declaration string) string {
		return regexp.MustCompile(`(?is)(\bencoding\s*=\s*["'])[^"']*(["'])`).ReplaceAllString(declaration, `${1}UTF-8${2}`)
	})
}

// repairShieldResponseMetadata runs only after a rewrite. It makes the
// response representation self-consistent and removes validators for the
// upstream bytes, without touching an unchanged response.
func repairShieldResponseMetadata(headers http.Header, pipeline shield.PipelineType, body []byte, convertedToUTF8 bool) {
	rawContentType := headers.Get("Content-Type")
	_, browserValidEssence := shieldMediaTypeEssence(rawContentType)
	mediaType, params, err := mime.ParseMediaType(rawContentType)
	if !browserValidEssence || err != nil || browserContentTypeIsGeneric(mediaType) {
		mediaType = shieldMediaType(pipeline)
		params = map[string]string{}
	}
	if convertedToUTF8 {
		params["charset"] = "utf-8"
	}
	headers.Set("Content-Type", mime.FormatMediaType(mediaType, params))
	headers.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	headers.Del("ETag")
	headers.Del("Digest")
	headers.Del("Content-MD5")
}

func shieldMediaType(pipeline shield.PipelineType) string {
	switch pipeline {
	case shield.PipelineSVG:
		return "image/svg+xml"
	case shield.PipelineXHTML:
		return "application/xhtml+xml"
	case shield.PipelineJS:
		return "application/javascript"
	default:
		return "text/html"
	}
}
