// Package shield implements inline HTML/JS rewriting that strips
// fingerprinting, extension probing, telemetry beacons, and agent traps
// from response bodies before the browser renders them.
//
// The engine compiles all detection patterns once at construction and reuses
// them across requests.  Three pipelines are supported:
//
//   - PipelineHTML: full rewriting (regex stripping + shim injection + element removal)
//   - PipelineJS:   regex stripping only (no DOM context, no shim injection)
//   - PipelineSVG:  extract <script> tags, apply the JS pipeline to their contents
package shield

import (
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// PipelineType determines which rewriting pipeline applies to a response.
type PipelineType int

const (
	// PipelineNone means the content type is not rewritable (images, JSON, etc.).
	PipelineNone PipelineType = iota
	// PipelineHTML applies full regex stripping, shim injection, and element removal.
	PipelineHTML
	// PipelineJS applies regex stripping only -- no DOM context for shim injection.
	PipelineJS
	// PipelineSVG extracts <script> blocks and runs the JS pipeline on their contents.
	PipelineSVG
)

// Result holds the outcome of a shield rewrite.
type Result struct {
	Rewritten     bool         // true if any content was modified
	Original      string       // original content preserved for dual-scan comparison
	Content       string       // rewritten content (identical to Original when Rewritten is false)
	ExtensionHits int          // chrome-extension:// / moz-extension:// patterns stripped
	TrackingHits  int          // tracking pixels, sendBeacon, prefetch links removed
	TrapHits      int          // hidden DOM traps and comment traps removed
	ShimInjected  bool         // true if a fingerprint/extension defense shim was prepended
	PipelineUsed  PipelineType // which pipeline was applied

	// SVG active content strip counts. SVGForeignObjectHits counts elided
	// <foreignObject> blocks (HTML-in-SVG embedding). SVGEventHandlerHits
	// counts onXxx attribute removals across all SVG elements.
	// SVGXlinkExternalHits counts external xlink:href references rewritten
	// away from absolute URLs. SVGHiddenTextHits counts hidden <text>
	// blocks removed (opacity:0 / display:none / visibility:hidden).
	SVGForeignObjectHits int
	SVGEventHandlerHits  int
	SVGXlinkExternalHits int
	SVGHiddenTextHits    int
}

// Engine compiles detection patterns once and reuses them across requests.
type Engine struct {
	extensionRe     *regexp.Regexp
	trackingPixelRe *regexp.Regexp
	hiddenTrapRe    *regexp.Regexp
	commentTrapRe   *regexp.Regexp
	functionStripRe *regexp.Regexp
	svgScriptRe     *regexp.Regexp // extracts <script>...</script> inside SVG

	// SVG active content regexes. Kept separate from the HTML/JS set so
	// a future SVG-only engine variant can initialize only the patterns
	// it needs, and so the SVG pipeline doesn't touch the hot HTML path.
	// External URL refs are split into xlink:href and plain href matchers
	// so each can be rewritten to its own attribute name (rewriting plain
	// href to xlink:href in SVG2 without the xmlns:xlink declaration
	// produces an unbound-prefix XML parse error).
	svgForeignObjectRe  *regexp.Regexp
	svgEventHandlerRe   *regexp.Regexp
	svgXlinkExternalRe  *regexp.Regexp
	svgHrefExternalRe   *regexp.Regexp
	svgHiddenTextStyle  *regexp.Regexp
	svgHiddenTextAttrRe *regexp.Regexp
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
	svgForeignRe, svgEventRe, svgXlinkRe, svgHrefRe, svgHiddenStyleRe, svgHiddenAttrRe := compileSVGActivePatterns()
	return &Engine{
		extensionRe:         extRe,
		trackingPixelRe:     trackRe,
		hiddenTrapRe:        trapRe,
		commentTrapRe:       commentRe,
		functionStripRe:     funcRe,
		svgScriptRe:         regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`),
		svgForeignObjectRe:  svgForeignRe,
		svgEventHandlerRe:   svgEventRe,
		svgXlinkExternalRe:  svgXlinkRe,
		svgHrefExternalRe:   svgHrefRe,
		svgHiddenTextStyle:  svgHiddenStyleRe,
		svgHiddenTextAttrRe: svgHiddenAttrRe,
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
	switch mt {
	case "text/html", "application/xhtml+xml":
		return PipelineHTML
	case "text/javascript", "application/javascript":
		return PipelineJS
	case "image/svg+xml":
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
		e.rewriteHTML(&res, cfg, headerNonce)
	case PipelineJS:
		e.rewriteJS(&res, cfg)
	case PipelineSVG:
		e.rewriteSVG(&res, cfg)
	}

	res.Rewritten = res.Content != res.Original
	return res
}

// rewriteHTML applies the full pipeline: regex stripping, trap removal, and
// optional shim injection. headerNonce overrides body-extracted nonce when
// non-empty (from CSP response header).
func (e *Engine) rewriteHTML(res *Result, cfg *config.BrowserShield, headerNonce string) {
	doc := res.Content

	// Extension probing.
	if cfg.StripExtensionProbing {
		doc, res.ExtensionHits = e.stripExtensions(doc)
	}

	// Tracking pixels and beacons.
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
		block := buildShimBlockWithNonce(shims, doc, headerNonce)
		doc = injectShim(doc, block)
		res.ShimInjected = true
	}

	res.Content = doc
}

// rewriteJS applies regex-only stripping (no DOM context).
func (e *Engine) rewriteJS(res *Result, cfg *config.BrowserShield) {
	js := res.Content

	if cfg.StripExtensionProbing {
		js, res.ExtensionHits = e.stripExtensions(js)
	}

	if cfg.StripTrackingPixels {
		var hits int
		js, hits = countReplace(e.trackingPixelRe, js)
		// Only sendBeacon applies to raw JS context; pixel regex won't match
		// but we run the combined pattern anyway for simplicity.
		res.TrackingHits = hits
	}

	res.Content = js
}

// rewriteSVG extracts <script> blocks, applies the JS pipeline to each, and
// reassembles the document. Then applies SVG-specific active content
// stripping: foreignObject elements, event handler attributes, external
// xlink:href references, and hidden <text> elements.
//
// Active content stripping always runs when the SVG pipeline is used — the
// browser shield is a fail-closed defensive layer, and SVG active content
// has no legitimate use in agent-visible responses. The strip passes are
// not gated behind StripHiddenTraps (which is an HTML concept) because
// they are SVG-specific and the config knob doesn't map cleanly.
func (e *Engine) rewriteSVG(res *Result, cfg *config.BrowserShield) {
	doc := res.Content
	doc = e.svgScriptRe.ReplaceAllStringFunc(doc, func(match string) string {
		sub := e.svgScriptRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		inner := sub[1]
		innerRes := Result{Original: inner, Content: inner, PipelineUsed: PipelineJS}
		e.rewriteJS(&innerRes, cfg)
		res.ExtensionHits += innerRes.ExtensionHits
		res.TrackingHits += innerRes.TrackingHits
		return strings.Replace(match, sub[1], innerRes.Content, 1)
	})

	// SVG active content stripping: foreignObject, event handlers, external
	// xlink:href / href references, and hidden text (both style= and
	// presentation-attribute forms). Each pass counts its own stat so the
	// caller can see exactly which vector fired.
	doc, res.SVGForeignObjectHits = countReplace(e.svgForeignObjectRe, doc)
	doc, res.SVGEventHandlerHits = countReplace(e.svgEventHandlerRe, doc)

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

// stripTracking removes tracking pixels, sendBeacon calls, and prefetch links.
func (e *Engine) stripTracking(s string) (string, int) {
	return countReplace(e.trackingPixelRe, s)
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
