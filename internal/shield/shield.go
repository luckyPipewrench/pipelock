// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package shield implements structural HTML and SVG rewriting that strips
// fingerprinting, extension probing, tracking elements, and agent traps from
// response bodies before the browser renders them. JavaScript responses and
// existing inline HTML scripts are never edited.
//
// The engine compiles all detection patterns once at construction and reuses
// them across requests. Four pipelines are supported:
//
//   - PipelineHTML: structural stripping outside scripts, plus optional shim injection
//   - PipelineXHTML: XML-compatible structural stripping outside scripts
//   - PipelineJS:   pass-through; scanning is owned by the response scanner
//   - PipelineSVG:  whole-element active-content removal
package shield

import (
	"bytes"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/media"
	"golang.org/x/net/html"
)

// PipelineType determines which rewriting pipeline applies to a response.
type PipelineType int

const (
	// PipelineNone means the content type is not rewritable (images, JSON, etc.).
	PipelineNone PipelineType = iota
	// PipelineHTML applies structural stripping outside existing script elements,
	// optional shim injection, and element removal.
	PipelineHTML
	// PipelineJS identifies JavaScript for shield reporting but never edits it.
	PipelineJS
	// PipelineSVG removes active-content elements rather than editing script bodies.
	PipelineSVG
	// PipelineXHTML applies HTML rewriting with XML self-closing-element rules.
	// It is distinct from PipelineHTML because <script/> is a script start tag in
	// text/html but an empty script element in application/xhtml+xml.
	PipelineXHTML
)

// Result holds the outcome of a shield rewrite.
type Result struct {
	Rewritten     bool         // true if any content was modified
	Original      string       // original content preserved for dual-scan comparison
	Content       string       // rewritten content (identical to Original when Rewritten is false)
	ExtensionHits int          // chrome-extension:// / moz-extension:// patterns stripped
	TrackingHits  int          // tracking pixels and prefetch links removed
	TrapHits      int          // hidden DOM traps and comment traps removed
	ShimInjected  bool         // true if a fingerprint/extension defense shim was prepended
	PipelineUsed  PipelineType // which pipeline was applied

	// SVG active content strip counts. SVGForeignObjectHits counts elided
	// <foreignObject> blocks (HTML-in-SVG embedding). SVGEventHandlerHits
	// counts onXxx attribute removals across all SVG elements.
	// SVGXlinkExternalHits counts external xlink:href references rewritten
	// away from absolute URLs. SVGHiddenTextHits counts hidden <text>
	// blocks removed (opacity:0 / display:none / visibility:hidden).
	SVGForeignObjectHits      int
	SVGScriptHits             int
	SVGEventHandlerHits       int
	SVGXlinkExternalHits      int
	SVGHiddenTextHits         int
	SVGAnimationInjectionHits int
}

// Engine compiles detection patterns once and reuses them across requests.
type Engine struct {
	extensionRe     *regexp.Regexp
	trackingPixelRe *regexp.Regexp
	hiddenTrapRe    *regexp.Regexp
	commentTrapRe   *regexp.Regexp
	functionStripRe *regexp.Regexp
	htmlScriptOpen  *regexp.Regexp // locates inline scripts that HTML passes must preserve
	htmlScriptClose *regexp.Regexp
	svgScriptRe     *regexp.Regexp // removes whole <script> elements inside SVG

	// SVG active content regexes. Kept separate from the HTML/JS set so
	// a future SVG-only engine variant can initialize only the patterns
	// it needs, and so the SVG pipeline doesn't touch the hot HTML path.
	// External URL refs are split into xlink:href and plain href matchers
	// so each can be rewritten to its own attribute name (rewriting plain
	// href to xlink:href in SVG2 without the xmlns:xlink declaration
	// produces an unbound-prefix XML parse error).
	svgForeignObjectRe      *regexp.Regexp
	svgEventHandlerRe       *regexp.Regexp
	svgXlinkExternalRe      *regexp.Regexp
	svgHrefExternalRe       *regexp.Regexp
	svgHiddenTextStyle      *regexp.Regexp
	svgHiddenTextAttrRe     *regexp.Regexp
	svgAnimationInjectionRe *regexp.Regexp
}

// NewEngine compiles all shield patterns and returns a ready-to-use engine.
// extraTrackingDomains are operator-supplied domains that are merged into
// the tracking pixel regex. Panics if any pattern is invalid.
func NewEngine(extraTrackingDomains []string) *Engine {
	extRe, trackRe, trapRe, commentRe, funcRe := compilePatterns()
	// Merge operator-supplied tracking domains into the compiled regex.
	if len(extraTrackingDomains) > 0 {
		extra := make([]string, 0, len(extraTrackingDomains))
		for _, d := range extraTrackingDomains {
			extra = append(extra, regexp.QuoteMeta(d))
		}
		merged := trackRe.String() + `|(?i)` + strings.Join(extra, "|")
		trackRe = regexp.MustCompile(merged)
	}
	svgForeignRe, svgEventRe, svgXlinkRe, svgHrefRe, svgHiddenStyleRe, svgHiddenAttrRe, svgAnimRe := compileSVGActivePatterns()
	return &Engine{
		extensionRe:             extRe,
		trackingPixelRe:         trackRe,
		hiddenTrapRe:            trapRe,
		commentTrapRe:           commentRe,
		functionStripRe:         funcRe,
		htmlScriptOpen:          regexp.MustCompile(`(?i)<script\b`),
		htmlScriptClose:         regexp.MustCompile(`(?is)</script\s*>`),
		svgScriptRe:             regexp.MustCompile(`(?is)<(?:[\w-]+:)?script\b[^>]*>.*?</(?:[\w-]+:)?script\s*>|<(?:[\w-]+:)?script\b[^>]*/\s*>`),
		svgForeignObjectRe:      svgForeignRe,
		svgEventHandlerRe:       svgEventRe,
		svgXlinkExternalRe:      svgXlinkRe,
		svgHrefExternalRe:       svgHrefRe,
		svgHiddenTextStyle:      svgHiddenStyleRe,
		svgHiddenTextAttrRe:     svgHiddenAttrRe,
		svgAnimationInjectionRe: svgAnimRe,
	}
}

// DetectPipeline determines the shield pipeline from a Content-Type header
// value and the first bytes of the response body.  When the Content-Type is
// missing or generic (application/octet-stream), net/http.DetectContentType
// is used as a fallback.
func DetectPipeline(contentType string, bodyPrefix []byte) PipelineType {
	if contentType != "" {
		// Parse media type, ignoring parameters (charset, boundary, etc.).
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if p := mediaTypeToPipeline(mediaType); p != PipelineNone {
			return p
		}
		// If the declared type is specific and unrecognised, trust it.
		if mediaType != "" && mediaType != "application/octet-stream" {
			return PipelineNone
		}
	}

	// Fallback: content sniffing.
	if len(bodyPrefix) > 0 {
		sniffed := http.DetectContentType(bodyPrefix)
		mediaType, _, _ := mime.ParseMediaType(sniffed)
		return mediaTypeToPipeline(mediaType)
	}

	return PipelineNone
}

// mediaTypeToPipeline maps a parsed media type string to a pipeline.
func mediaTypeToPipeline(mt string) PipelineType {
	switch {
	case mt == "text/html":
		return PipelineHTML
	case mt == "application/xhtml+xml":
		return PipelineXHTML
	// RFC 9239 section 6: historical JavaScript registrations are aliases
	// with equivalent processing requirements. The table is shared with
	// internal/config's unscannable-passthrough classifier so the two
	// cannot drift apart; see internal/media.JavaScriptMediaTypes.
	case media.IsJavaScriptMediaType(mt):
		return PipelineJS
	case mt == "image/svg+xml":
		return PipelineSVG
	default:
		return PipelineNone
	}
}

// Rewrite applies the shield pipeline to content.
// cfg controls which categories are active. A nil cfg disables all rewriting.
func (e *Engine) Rewrite(content string, pipeline PipelineType, cfg *config.BrowserShield) Result {
	return e.RewriteWithNonce(content, pipeline, cfg, "")
}

// RewriteWithNonce applies the shield pipeline with an optional CSP nonce
// extracted from response headers. When headerNonce is non-empty, the injected
// shim <script> tag uses it instead of scanning the document body for a nonce.
func (e *Engine) RewriteWithNonce(content string, pipeline PipelineType, cfg *config.BrowserShield, headerNonce string) Result {
	res := Result{
		Original:     content,
		Content:      content,
		PipelineUsed: pipeline,
	}

	if cfg == nil || pipeline == PipelineNone {
		return res
	}

	switch pipeline {
	case PipelineHTML:
		e.rewriteHTML(&res, cfg, headerNonce, false)
	case PipelineXHTML:
		e.rewriteHTML(&res, cfg, headerNonce, true)
	case PipelineSVG:
		e.rewriteSVG(&res, cfg)
	}

	res.Rewritten = res.Content != res.Original
	return res
}

// rewriteHTML applies the full pipeline: regex stripping, trap removal, and
// optional shim injection. headerNonce overrides body-extracted nonce when
// non-empty (from CSP response header).
func (e *Engine) rewriteHTML(res *Result, cfg *config.BrowserShield, headerNonce string, allowSelfClosingScripts bool) {
	originalDoc := res.Content
	doc, scripts := e.maskHTMLScriptsWithSelfClosing(res.Content, allowSelfClosingScripts)

	// Extension probing.
	if cfg.StripExtensionProbing {
		doc, res.ExtensionHits = e.stripExtensions(doc)
	}

	// Tracking elements.
	if cfg.StripTrackingPixels {
		doc, res.TrackingHits = e.stripTracking(doc)
	}

	// Hidden traps (elements + comments).
	if cfg.StripHiddenTraps {
		doc, res.TrapHits = e.stripTraps(doc, cfg.Strictness)
	}

	// Shim injection.
	shims := e.buildShimList(cfg)
	if len(shims) > 0 {
		block := buildShimBlockWithNonce(shims, originalDoc, headerNonce)
		doc = injectShim(doc, block)
		res.ShimInjected = true
	}

	res.Content = restoreHTMLScripts(doc, scripts)
}

// rewriteSVG removes whole <script> elements, then applies SVG-specific active
// content stripping: foreignObject elements, event handler attributes, external
// xlink:href references, and hidden <text> elements. Removing a complete SVG
// element cannot leave a partially rewritten JavaScript expression behind.
//
// Active content stripping always runs when the SVG pipeline is used - the
// browser shield is a fail-closed defensive layer, and SVG active content
// has no legitimate use in agent-visible responses. The strip passes are
// not gated behind StripHiddenTraps (which is an HTML concept) because
// they are SVG-specific and the config knob doesn't map cleanly.
func (e *Engine) rewriteSVG(res *Result, cfg *config.BrowserShield) {
	doc := res.Content
	doc, res.SVGScriptHits = countReplace(e.svgScriptRe, doc)

	// SVG active content stripping: foreignObject, event handlers, external
	// xlink:href / href references, and hidden text (both style= and
	// presentation-attribute forms). Each pass counts its own stat so the
	// caller can see exactly which vector fired.
	doc, res.SVGForeignObjectHits = countReplace(e.svgForeignObjectRe, doc)
	doc, res.SVGEventHandlerHits = countReplace(e.svgEventHandlerRe, doc)
	doc, res.SVGAnimationInjectionHits = countReplace(e.svgAnimationInjectionRe, doc)

	// Rewrite each external ref form back to its own attribute name so the
	// output stays well-formed XML. Without the split, plain href in an
	// SVG2 document (with no xmlns:xlink) would be rewritten to xlink:href
	// and fail to parse under a strict XML parser.
	var xlinkHits, hrefHits int
	doc, xlinkHits = countReplaceFunc(e.svgXlinkExternalRe, doc, func(_ string) string {
		return ` xlink:href="#_stripped"`
	})
	doc, hrefHits = countReplaceFunc(e.svgHrefExternalRe, doc, func(_ string) string {
		return ` href="#_stripped"`
	})
	res.SVGXlinkExternalHits = xlinkHits + hrefHits

	// Hidden <text>: both inline style= form and SVG presentation
	// attributes (display="none", visibility="hidden", opacity="0").
	var hiddenStyleHits, hiddenAttrHits int
	doc, hiddenStyleHits = countReplace(e.svgHiddenTextStyle, doc)
	doc, hiddenAttrHits = countReplace(e.svgHiddenTextAttrRe, doc)
	res.SVGHiddenTextHits = hiddenStyleHits + hiddenAttrHits

	// Strip hidden traps in the SVG XML body outside scripts.
	if cfg.StripHiddenTraps {
		var trapHits int
		doc, trapHits = e.stripTraps(doc, cfg.Strictness)
		res.TrapHits += trapHits
	}

	res.Content = doc
}

// stripExtensions removes extension-probing URLs and function names.
func (e *Engine) stripExtensions(s string) (string, int) {
	total := 0
	s, n := countReplace(e.extensionRe, s)
	total += n
	s, n = countReplace(e.functionStripRe, s)
	total += n
	return s, total
}

// stripTracking removes tracking pixels and prefetch links.
func (e *Engine) stripTracking(s string) (string, int) {
	return countReplace(e.trackingPixelRe, s)
}

// maskedHTMLScript records an existing HTML script block under a collision-free
// placeholder. Masking keeps every HTML regex pass away from JavaScript while
// still allowing a containing hidden HTML element to be removed as a unit.
type maskedHTMLScript struct {
	placeholder string
	content     string
}

func (e *Engine) maskHTMLScripts(doc string) (string, []maskedHTMLScript) {
	prefix := "\x00pipelock-inline-script-"
	for strings.Contains(doc, prefix) {
		prefix += "x"
	}

	var masked, script strings.Builder
	var scripts []maskedHTMLScript
	inScript := false
	z := html.NewTokenizer(strings.NewReader(doc))
	for {
		tokenType := z.Next()
		raw := string(z.Raw())
		if tokenType == html.ErrorToken {
			if inScript {
				script.WriteString(raw)
				placeholder := prefix + strconv.Itoa(len(scripts)) + "\x00"
				scripts = append(scripts, maskedHTMLScript{placeholder: placeholder, content: script.String()})
				masked.WriteString(placeholder)
			} else {
				masked.WriteString(raw)
			}
			break
		}

		isScript := false
		if tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken || tokenType == html.EndTagToken {
			name, _ := z.TagName()
			isScript = bytes.EqualFold(name, []byte("script"))
		}

		if inScript {
			script.WriteString(raw)
			if tokenType == html.EndTagToken && isScript {
				placeholder := prefix + strconv.Itoa(len(scripts)) + "\x00"
				scripts = append(scripts, maskedHTMLScript{placeholder: placeholder, content: script.String()})
				masked.WriteString(placeholder)
				script.Reset()
				inScript = false
			}
			continue
		}

		if (tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken) && isScript {
			script.WriteString(raw)
			inScript = true
			continue
		}
		masked.WriteString(raw)
	}

	return masked.String(), scripts
}

func (e *Engine) maskHTMLScriptsWithSelfClosing(doc string, allowSelfClosingScripts bool) (string, []maskedHTMLScript) {
	if !allowSelfClosingScripts {
		return e.maskHTMLScripts(doc)
	}

	prefix := "\x00pipelock-inline-script-"
	for strings.Contains(doc, prefix) {
		prefix += "x"
	}

	var masked strings.Builder
	var scripts []maskedHTMLScript
	remaining := doc
	for {
		open := e.findHTMLScriptOpenWithCDATA(remaining, allowSelfClosingScripts)
		if open < 0 {
			masked.WriteString(remaining)
			break
		}

		masked.WriteString(remaining[:open])
		fromOpen := remaining[open:]
		end := len(fromOpen)
		if openTagEnd := htmlTagEnd(fromOpen); openTagEnd >= 0 {
			openTag := strings.TrimSpace(fromOpen[:openTagEnd-1])
			if allowSelfClosingScripts && strings.HasSuffix(openTag, "/") {
				end = openTagEnd
			} else if closeTag := e.htmlScriptClose.FindStringIndex(fromOpen[openTagEnd:]); closeTag != nil {
				end = openTagEnd + closeTag[1]
			}
		}

		placeholder := prefix + strconv.Itoa(len(scripts)) + "\x00"
		scripts = append(scripts, maskedHTMLScript{placeholder: placeholder, content: fromOpen[:end]})
		masked.WriteString(placeholder)
		remaining = fromOpen[end:]
	}

	return masked.String(), scripts
}

func (e *Engine) findHTMLScriptOpen(doc string) int {
	return e.findHTMLScriptOpenWithCDATA(doc, false)
}

func (e *Engine) findHTMLScriptOpenWithCDATA(doc string, allowCDATA bool) int {
	for offset := 0; offset < len(doc); {
		relative := strings.IndexByte(doc[offset:], '<')
		if relative < 0 {
			return -1
		}
		candidate := offset + relative
		rest := doc[candidate:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				return -1
			}
			offset = candidate + 4 + end + len("-->")
			continue
		case allowCDATA && strings.HasPrefix(rest, "<![CDATA["):
			end := strings.Index(rest[9:], "]]>")
			if end < 0 {
				return -1
			}
			offset = candidate + 9 + end + len("]]>")
			continue
		}

		if match := e.htmlScriptOpen.FindStringIndex(rest); match != nil && match[0] == 0 {
			return candidate
		}
		end := htmlTagEnd(rest)
		if end < 0 {
			return -1
		}
		offset = candidate + end
	}
	return -1
}

func htmlTagEnd(tag string) int {
	var quote byte
	for i := 1; i < len(tag); i++ {
		switch {
		case quote != 0 && tag[i] == quote:
			quote = 0
		case quote == 0 && (tag[i] == '\'' || tag[i] == '"'):
			quote = tag[i]
		case quote == 0 && tag[i] == '>':
			return i + 1
		}
	}
	return -1
}

func restoreHTMLScripts(doc string, scripts []maskedHTMLScript) string {
	for _, script := range scripts {
		doc = strings.ReplaceAll(doc, script.placeholder, script.content)
	}
	return doc
}

// stripTraps removes hidden DOM traps and comment traps.
// Under aggressive strictness, comment traps are always stripped.
// Under minimal strictness, only hidden-element traps are stripped.
func (e *Engine) stripTraps(s string, strictness string) (string, int) {
	total := 0

	// Hidden elements are stripped at all strictness levels.
	s, n := countReplace(e.hiddenTrapRe, s)
	total += n

	// Comment traps are stripped at standard and aggressive.
	if strictness != config.ShieldStrictnessMinimal {
		s, n = countReplace(e.commentTrapRe, s)
		total += n
	}

	return s, total
}

// buildShimList assembles the ordered list of shim scripts to inject.
func (e *Engine) buildShimList(cfg *config.BrowserShield) []string {
	var shims []string
	if cfg.StripExtensionProbing {
		shims = append(shims, ExtensionProbeShim)
	}
	if cfg.InjectFingerprintShims {
		shims = append(shims, FingerprintShim)
	}
	return shims
}

// cspNonceRe extracts 'nonce-xxx' from Content-Security-Policy headers.
// Compiled once at package level rather than per-call.
var cspNonceRe = regexp.MustCompile(`'nonce-([A-Za-z0-9+/=]+)'`)

// ExtractCSPNonce extracts a CSP nonce value from the Content-Security-Policy
// response header. Returns the first nonce found in any script-src directive,
// or "" if none is present. This allows the shield shim injection to reuse the
// page's existing CSP nonce instead of being blocked by the policy.
func ExtractCSPNonce(headers http.Header) string {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return ""
	}
	if m := cspNonceRe.FindStringSubmatch(csp); len(m) > 1 {
		return m[1]
	}
	return ""
}

// countReplace replaces all matches with empty string and returns the
// modified string and the number of replacements made.
func countReplace(re *regexp.Regexp, s string) (string, int) {
	matches := re.FindAllStringIndex(s, -1)
	n := len(matches)
	if n == 0 {
		return s, 0
	}
	return re.ReplaceAllString(s, ""), n
}

// countReplaceFunc is the callback variant of countReplace. Used for SVG
// xlink:href rewriting where the replacement is a fixed safe attribute
// rather than an empty string, so the element tag structure stays valid.
func countReplaceFunc(re *regexp.Regexp, s string, repl func(match string) string) (string, int) {
	matches := re.FindAllStringIndex(s, -1)
	n := len(matches)
	if n == 0 {
		return s, 0
	}
	return re.ReplaceAllStringFunc(s, repl), n
}
