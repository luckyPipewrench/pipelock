package shield

import "regexp"

// Extension probing patterns.
//
// These detect JavaScript and HTML constructs used by sites (e.g. LinkedIn's
// BrowserGate) to fingerprint installed browser extensions.  Matching is
// case-insensitive because real-world probing code uses mixed casing.

// extensionURLPattern matches chrome-extension:// and moz-extension:// URIs
// inside string literals or HTML attributes.  The 32-char lowercase hex ID is
// the canonical Chrome format; moz-extension uses UUIDs but we only need the
// scheme prefix to neutralise the probe.
const extensionURLPattern = `(?i)(?:chrome|moz)-extension://[a-z0-9-]*`

// extensionRuntimePattern matches direct chrome.runtime.sendMessage calls.
const extensionRuntimePattern = `(?i)chrome\.runtime\.sendMessage`

// extensionFuncPattern matches known probing function names.
const extensionFuncPattern = `(?i)\b(?:fetchExtensions|scanDOMForPrefix|fireExtensionDetectedEvents)\b`

// Tracking pixel / beacon patterns.

// trackingPixelPattern matches 1x1 image tags where width=1 and height=1
// appear anywhere in the tag (not necessarily adjacent, other attributes
// like src may appear between them).
const trackingPixelPattern = `(?i)<img[^>]+\bwidth\s*=\s*["']?1["']?[^>]+\bheight\s*=\s*["']?1["']?[^>]*>` +
	`|` +
	`(?i)<img[^>]+\bheight\s*=\s*["']?1["']?[^>]+\bwidth\s*=\s*["']?1["']?[^>]*>`

// sendBeaconPattern matches navigator.sendBeacon() calls.
const sendBeaconPattern = `(?i)navigator\.sendBeacon\s*\(`

// prefetchPattern matches <link rel="prefetch"> tags.
const prefetchPattern = `(?i)<link[^>]+rel\s*=\s*["']?prefetch["']?[^>]*>`

// Hidden trap patterns.

// commentTrapPattern matches HTML comments containing instruction-like keywords
// that could be prompt injections hidden from rendering.
const commentTrapPattern = `(?i)<!--[\s\S]*?(?:ignore|disregard|forget|override|instead|instruction)[\s\S]*?-->`

// hiddenElementPattern matches elements hidden via CSS that could contain
// injected instructions invisible to the user but visible to an AI agent
// reading the DOM.
const hiddenElementPattern = `(?i)<(?:div|span|p)[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden)[^"']*["'][^>]*>[\s\S]*?</(?:div|span|p)>`

// ariaHiddenTrapPattern matches aria-hidden elements containing instruction
// keywords.
const ariaHiddenTrapPattern = `(?i)<[^>]+aria-hidden\s*=\s*["']true["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|instruction)[^<]*</[^>]+>`

// SVG active content patterns. Applied in rewriteSVG after the existing
// <script> extraction pass. Regex-based for consistency with the rest of
// the shield pipeline; known fragile against pathological XML (unbalanced
// elements, attribute-order tricks, CDATA sections) but matches the
// best-effort defensive posture of the shield layer.

// svgForeignObjectPattern matches <foreignObject>...</foreignObject> blocks.
// foreignObject can embed arbitrary HTML — including iframes and script
// tags — inside SVG, turning a nominally-image response into active web
// content. Strip the whole element with its children.
//
// The optional `[\w-]+:` prefix matches namespace-prefixed element names
// like `<svg:foreignObject>` and `<s:foreignObject>`. SVG documents that
// declare the svg namespace as a prefix rather than the default namespace
// use this form, and omitting it would leave the attack surface open to a
// trivial xmlns:svg="http://www.w3.org/2000/svg" relabeling.
const svgForeignObjectPattern = `(?is)<(?:[\w-]+:)?foreignObject\b[^>]*>.*?</(?:[\w-]+:)?foreignObject>`

// svgSelfClosingForeignObjectPattern catches the self-closing variant
// <foreignObject .../> which some writers produce when the element has no
// children. Covered separately because the greedy non-self-closing match
// wouldn't catch it.
const svgSelfClosingForeignObjectPattern = `(?i)<(?:[\w-]+:)?foreignObject\b[^>]*/>`

// svgEventHandlerPattern matches DOM event handler attributes on any SVG
// element (onload, onclick, onerror, onmouseover, onfocus, etc.). The
// pattern captures the leading whitespace so the resulting element tag
// remains well-formed after removal. Quoted value handling covers both
// single and double quotes.
const svgEventHandlerPattern = `(?i)\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*')`

// svgExternalXlinkHrefPattern matches the namespaced xlink:href attribute
// when its value is NOT a local fragment reference (#anchor). Split from
// the plain href form so each variant can be rewritten back to its own
// attribute name (rewriting plain href to xlink:href in an SVG2 document
// without xmlns:xlink declared produces an unbound-prefix parse error).
const svgExternalXlinkHrefPattern = `(?i)\s+xlink:href\s*=\s*(?:"[^"#][^"]*"|'[^'#][^']*')`

// svgExternalHrefPattern matches the plain href attribute (SVG2) when its
// value is NOT a local fragment reference. Matches only on SVG elements
// where href is a real reference target (use, image, a, link) to avoid
// stripping unrelated HTML contexts — but since this pattern is only
// invoked from the SVG pipeline, the source doc is already known to be
// SVG and matching any href= on any element is safe.
const svgExternalHrefPattern = `(?i)\s+href\s*=\s*(?:"[^"#][^"]*"|'[^'#][^']*')`

// svgHiddenTextStylePattern matches <text> elements whose inline style
// makes them invisible to visual rendering while remaining in the DOM for
// LLM consumption. The `(?:[\w-]+:)?` prefix covers namespace-prefixed
// element names like `<svg:text ...>` that would otherwise bypass the
// bare-name match.
const svgHiddenTextStylePattern = `(?is)<(?:[\w-]+:)?text\b[^>]*style\s*=\s*["'][^"']*(?:opacity\s*:\s*0(?:\.0+)?|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>.*?</(?:[\w-]+:)?text>`

// svgHiddenTextAttrPattern matches <text> elements that use SVG
// presentation attributes (display, visibility, opacity) directly on the
// element rather than in an inline style. SVG 1.1 allows these as first-
// class attributes, so relying only on style="..." would miss the simplest
// form of the attack: <text display="none">payload</text>. Same
// namespace-prefix handling as svgHiddenTextStylePattern.
const svgHiddenTextAttrPattern = `(?is)<(?:[\w-]+:)?text\b[^>]*(?:\bdisplay\s*=\s*["']none["']|\bvisibility\s*=\s*["']hidden["']|\bopacity\s*=\s*["']0(?:\.0+)?["'])[^>]*>.*?</(?:[\w-]+:)?text>`

// compilePatterns compiles all shield patterns into regexp objects.
// Called once from NewEngine; panics on invalid regex (programming error).
func compilePatterns() (
	extensionRe,
	trackingPixelRe,
	hiddenTrapRe,
	commentTrapRe,
	functionStripRe *regexp.Regexp,
) {
	extensionRe = regexp.MustCompile(extensionURLPattern + `|` + extensionRuntimePattern)
	trackingPixelRe = regexp.MustCompile(trackingPixelPattern + `|` + sendBeaconPattern + `|` + prefetchPattern)
	hiddenTrapRe = regexp.MustCompile(hiddenElementPattern + `|` + ariaHiddenTrapPattern)
	commentTrapRe = regexp.MustCompile(commentTrapPattern)
	functionStripRe = regexp.MustCompile(extensionFuncPattern)
	return
}

// compileSVGActivePatterns compiles the SVG-specific active content patterns.
// Returned separately from compilePatterns so the shield.Engine can keep its
// SVG regex state distinct from the HTML/JS regex state and avoid touching
// hot paths when SVG pipeline runs. Each strip concern has its own compiled
// regex so per-pass stats remain accurate.
func compileSVGActivePatterns() (
	foreignObjectRe,
	eventHandlerRe,
	xlinkExternalRe,
	hrefExternalRe,
	hiddenTextStyleRe,
	hiddenTextAttrRe *regexp.Regexp,
) {
	foreignObjectRe = regexp.MustCompile(svgForeignObjectPattern + `|` + svgSelfClosingForeignObjectPattern)
	eventHandlerRe = regexp.MustCompile(svgEventHandlerPattern)
	xlinkExternalRe = regexp.MustCompile(svgExternalXlinkHrefPattern)
	hrefExternalRe = regexp.MustCompile(svgExternalHrefPattern)
	hiddenTextStyleRe = regexp.MustCompile(svgHiddenTextStylePattern)
	hiddenTextAttrRe = regexp.MustCompile(svgHiddenTextAttrPattern)
	return
}
