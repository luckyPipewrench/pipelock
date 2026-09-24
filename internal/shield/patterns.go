// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"regexp"
	"strings"
)

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

// Tracking element patterns.

// trackingPixelPattern matches 1x1 image tags where width=1 and height=1
// appear anywhere in the tag (not necessarily adjacent, other attributes
// like src may appear between them).
const trackingPixelPattern = `(?i)<img[^>]+\bwidth\s*=\s*["']?1["']?[^>]+\bheight\s*=\s*["']?1["']?[^>]*>` +
	`|` +
	`(?i)<img[^>]+\bheight\s*=\s*["']?1["']?[^>]+\bwidth\s*=\s*["']?1["']?[^>]*>`

// prefetchPattern matches <link rel="prefetch"> tags.
const prefetchPattern = `(?i)<link[^>]+rel\s*=\s*["']?prefetch["']?[^>]*>`

// Hidden trap patterns.

// commentTrapPattern matches HTML comments containing instruction-like keywords
// that could be prompt injections hidden from rendering.
const commentTrapPattern = `(?i)<!--[\s\S]*?(?:ignore|disregard|forget|override|instead|instruction)[\s\S]*?-->`

// hiddenElementOpenPattern matches the OPENING tag of a div, span or p hidden
// via CSS. The element's extent is found by balanced tag counting in
// stripHiddenElementTraps, not by the regex: a lazy match to the first close
// tag cut nested markup in half and left the page structurally broken.
const hiddenElementOpenPattern = `(?i)<(div|span|p)\b[^>]*\bstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden)[^"']*["'][^>]*>`

// trapInstructionPattern is the instruction vocabulary every trap rule keys
// on. A hidden element, comment or aria-hidden node is removed only when its
// text carries one of these words; ordinary hidden UI (menus, modals,
// templates) is left intact.
const trapInstructionPattern = `(?i)ignore|disregard|forget|override|instead|instruction`

// ariaHiddenTrapPattern matches aria-hidden elements containing instruction
// keywords.
const ariaHiddenTrapPattern = `(?i)<[^>]+aria-hidden\s*=\s*["']true["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|instruction)[^<]*</[^>]+>`

// SVG active content patterns. Applied in rewriteSVG after the existing
// <script> extraction pass. Regex-based for consistency with the rest of
// the shield pipeline; known fragile against pathological XML (unbalanced
// elements, attribute-order tricks, CDATA sections) but matches the
// best-effort defensive posture of the shield layer.

// svgForeignObjectPattern matches <foreignObject>...</foreignObject> blocks.
// foreignObject can embed arbitrary HTML - including iframes and script
// tags - inside SVG, turning a nominally-image response into active web
// content. Strip the whole element with its children.
//
// The optional `[\w.-]+:` prefix matches namespace-prefixed element names.
// The grammar includes a dot because an XML NCName permits one: a document
// declaring xmlns:x.y and writing <x.y:script> is valid and executes, and a
// prefix pattern without the dot left that element in place.
// like `<svg:foreignObject>` and `<s:foreignObject>`. SVG documents that
// declare the svg namespace as a prefix rather than the default namespace
// use this form, and omitting it would leave the attack surface open to a
// trivial xmlns:svg="http://www.w3.org/2000/svg" relabeling.
const svgForeignObjectPattern = `(?is)<(?:[\w.-]+:)?foreignObject\b[^>]*>.*?</(?:[\w.-]+:)?foreignObject>`

// svgSelfClosingForeignObjectPattern catches the self-closing variant
// <foreignObject .../> which some writers produce when the element has no
// children. Covered separately because the greedy non-self-closing match
// wouldn't catch it.
const svgSelfClosingForeignObjectPattern = `(?i)<(?:[\w.-]+:)?foreignObject\b[^>]*/>`

// svgEventHandlerPattern matches DOM event handler attributes on any SVG
// element (onload, onclick, onerror, onmouseover, onfocus, etc.). The
// pattern captures the leading whitespace so the resulting element tag
// remains well-formed after removal. Quoted value handling covers both
// single and double quotes. The third alternative catches unquoted values
// (valid in HTML parsing contexts and some SVG serializers) - the value
// runs until the next whitespace, >, or />.
const svgEventHandlerPattern = `(?i)\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>"'/][^\s>"'/]*)`

// svgExternalXlinkHrefPattern matches the namespaced xlink:href attribute
// when its value is NOT a local fragment reference (#anchor). Split from
// the plain href form so each variant can be rewritten back to its own
// attribute name (rewriting plain href to xlink:href in an SVG2 document
// without xmlns:xlink declared produces an unbound-prefix parse error).
const svgExternalXlinkHrefPattern = `(?i)\s+xlink:href\s*=\s*(?:"[^"#][^"]*"|'[^'#][^']*')`

// svgExternalHrefPattern matches the plain href attribute (SVG2) when its
// value is NOT a local fragment reference. Matches only on SVG elements
// where href is a real reference target (use, image, a, link) to avoid
// stripping unrelated HTML contexts - but since this pattern is only
// invoked from the SVG pipeline, the source doc is already known to be
// SVG and matching any href= on any element is safe.
const svgExternalHrefPattern = `(?i)\s+href\s*=\s*(?:"[^"#][^"]*"|'[^'#][^']*')`

// svgHiddenTextStylePattern matches <text> elements whose inline style
// makes them invisible to visual rendering while remaining in the DOM for
// LLM consumption. The `(?:[\w.-]+:)?` prefix covers namespace-prefixed
// element names like `<svg:text ...>` that would otherwise bypass the
// bare-name match.
const svgHiddenTextStylePattern = `(?is)<(?:[\w.-]+:)?text\b[^>]*style\s*=\s*["'][^"']*(?:opacity\s*:\s*0(?:\.0+)?|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>.*?</(?:[\w.-]+:)?text>`

// svgHiddenTextAttrPattern matches <text> elements that use SVG
// presentation attributes (display, visibility, opacity) directly on the
// element rather than in an inline style. SVG 1.1 allows these as first-
// class attributes, so relying only on style="..." would miss the simplest
// form of the attack: <text display="none">payload</text>. Same
// namespace-prefix handling as svgHiddenTextStylePattern.
const svgHiddenTextAttrPattern = `(?is)<(?:[\w.-]+:)?text\b[^>]*(?:\bdisplay\s*=\s*["']none["']|\bvisibility\s*=\s*["']hidden["']|\bopacity\s*=\s*["']0(?:\.0+)?["'])[^>]*>.*?</(?:[\w.-]+:)?text>`

// svgAnimationInjectionPattern matches SVG animation elements that target
// event handler attributes. <set attributeName="onload" to="alert(1)"/> and
// <animate attributeName="onclick" ...> can inject active content without
// any direct on* attribute on the target element - the animation engine
// sets the attribute at runtime. The pattern matches <animate>, <set>,
// <animateTransform>, and <animateMotion> elements where attributeName
// points to an event handler (on*). Namespace-prefixed forms included.
const svgAnimationInjectionPattern = `(?is)<(?:[\w.-]+:)?(?:animate|set|animateTransform|animateMotion)\b[^>]*\battributeName\s*=\s*(?:"on[a-z]+"|'on[a-z]+'|on[a-z]+)[^>]*/?>(?:.*?</(?:[\w.-]+:)?(?:animate|set|animateTransform|animateMotion)>)?`

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
	trackingPixelRe = regexp.MustCompile(trackingPixelPattern + `|` + prefetchPattern)
	hiddenTrapRe = regexp.MustCompile(ariaHiddenTrapPattern)
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
	hiddenTextAttrRe,
	animationInjectionRe *regexp.Regexp,
) {
	foreignObjectRe = regexp.MustCompile(svgForeignObjectPattern + `|` + svgSelfClosingForeignObjectPattern)
	eventHandlerRe = regexp.MustCompile(svgEventHandlerPattern)
	xlinkExternalRe = regexp.MustCompile(svgExternalXlinkHrefPattern)
	hrefExternalRe = regexp.MustCompile(svgExternalHrefPattern)
	hiddenTextStyleRe = regexp.MustCompile(svgHiddenTextStylePattern)
	hiddenTextAttrRe = regexp.MustCompile(svgHiddenTextAttrPattern)
	animationInjectionRe = regexp.MustCompile(svgAnimationInjectionPattern)
	return
}

var (
	hiddenElementOpenRe = regexp.MustCompile(hiddenElementOpenPattern)
	trapInstructionRe   = regexp.MustCompile(trapInstructionPattern)
)

// stripHiddenElementTraps removes each CSS-hidden div, span or p whose text
// carries instruction vocabulary. The whole element is removed, from its
// opening tag to its matching close tag, so the rest of the document keeps
// its structure. An element with no matching close runs to the end of the
// document, as a browser would parse it.
func stripHiddenElementTraps(s string) (string, int) {
	var b strings.Builder
	lower := asciiLower(s)
	hits := 0
	pos := 0
	for pos < len(s) {
		loc := hiddenElementOpenRe.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		start, openEnd := pos+loc[0], pos+loc[1]
		tag := strings.ToLower(s[pos+loc[2] : pos+loc[3]])
		end := matchingCloseEnd(lower, openEnd, tag)
		inner := s[openEnd:end]
		if closeStart := strings.LastIndex(asciiLower(inner), "</"+tag); closeStart >= 0 {
			inner = inner[:closeStart]
		}
		// Only a text-only hidden element is a trap. A hidden element that
		// holds markup is interface: applications hide whole views, menus
		// and templates until their scripts reveal them, and removing one
		// because its text happens to contain "instead" deleted the page.
		// Its text is still read by response scanning.
		if strings.Contains(inner, "<") || !trapInstructionRe.MatchString(inner) {
			b.WriteString(s[pos:openEnd])
			pos = openEnd
			continue
		}
		b.WriteString(s[pos:start])
		pos = end
		hits++
	}
	if hits == 0 {
		return s, 0
	}
	b.WriteString(s[pos:])
	return b.String(), hits
}

// matchingCloseEnd returns the offset just past the close tag that balances
// an element opened before from, counting nested elements of the same name.
// lower is the document folded by asciiLower, computed once by the caller. It returns len(lower) when
// the element is never closed.
func matchingCloseEnd(lower string, from int, tag string) int {
	depth := 1
	i := from
	for {
		next := strings.Index(lower[i:], "<")
		if next < 0 {
			return len(lower)
		}
		i += next
		rest := lower[i:]
		switch {
		case strings.HasPrefix(rest, "</"+tag) && tagNameEnds(rest, len(tag)+2):
			depth--
			closeEnd := strings.IndexByte(rest, '>')
			if closeEnd < 0 {
				return len(lower)
			}
			if depth == 0 {
				return i + closeEnd + 1
			}
			i += closeEnd + 1
		case strings.HasPrefix(rest, "<"+tag) && tagNameEnds(rest, len(tag)+1):
			depth++
			i += len(tag) + 1
		default:
			i++
		}
	}
}

// tagNameEnds reports whether the tag name in rest stops at offset n, so
// <p> matches p while <param> and <picture> do not.
func tagNameEnds(rest string, n int) bool {
	if n >= len(rest) {
		return true
	}
	switch rest[n] {
	case '>', '/', ' ', '\t', '\n', '\r', '\f':
		return true
	}
	return false
}

// asciiLower folds only A-Z. Unicode case folding can change a string's byte
// length, which would misalign offsets computed on the folded copy.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
