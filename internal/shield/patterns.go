// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"regexp"
	"sort"
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

// trapInstructionPattern is the instruction vocabulary every trap rule keys
// on. A hidden element, comment or aria-hidden node is removed only when its
// text carries one of these words; ordinary hidden UI (menus, modals,
// templates) is left intact.
const trapInstructionPattern = `(?i)ignore|disregard|forget|override|instead|instruction`

// ariaHiddenTrapPattern matches aria-hidden elements containing instruction
// keywords.
const ariaHiddenTrapPattern = `(?i)<[^>]*\saria-hidden\s*=\s*["']true["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|instruction)[^<]*</[^>]+>`

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
const svgHiddenTextStylePattern = `(?is)<(?:[\w.-]+:)?text\b[^>]*\sstyle\s*=\s*["'][^"']*(?:opacity\s*:\s*0(?:\.0+)?|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>.*?</(?:[\w.-]+:)?text>`

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

var trapInstructionRe = regexp.MustCompile(trapInstructionPattern)

// hiddenCSSDeclRe matches one CSS declaration that hides content, with the
// whole value checked so opacity:0.5 or font-size:0.8em is not read as zero.
var hiddenCSSDeclRe = regexp.MustCompile(`(?i)(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|pc|in|cm|mm|q|em|ex|ch|rem|lh|rlh|cap|rcap|rex|ric|vw|vh|vi|vb|vmin|vmax|svw|svh|svi|svb|svmin|svmax|lvw|lvh|lvi|lvb|lvmin|lvmax|dvw|dvh|dvi|dvb|dvmin|dvmax|cqw|cqh|cqi|cqb|cqmin|cqmax|%)?|opacity\s*:\s*0(?:\.0+)?%?)\s*(?:!\s*important\s*)?(?:;|$)`)

// tagEnd returns the offset just past the '>' that closes the tag starting at
// lt, skipping any '>' inside a quoted attribute value, or -1 when the tag
// never closes. A quote opens a value only right after '=', as HTML parses it.
func tagEnd(s string, lt int) int {
	quote := byte(0)
	afterEq, unquotedValue := false, false
	for i := lt + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '>':
			return i + 1
		case unquotedValue:
			// Quotes and '=' inside an unquoted value are ordinary text.
			if isHTMLSpace(c) {
				unquotedValue = false
			}
		case c == '=':
			afterEq = true
		case isHTMLSpace(c):
			// Whitespace between '=' and a value keeps afterEq.
		case afterEq && (c == '"' || c == '\''):
			quote = c
			afterEq = false
		default:
			// A quote in an attribute name is ordinary text; only a quote
			// right after '=' opens a quoted value.
			unquotedValue = afterEq
			afterEq = false
		}
	}
	return -1
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// tagAttribute returns the value of the named attribute (lowercase) in an
// opening tag, reading only real attribute positions: text that looks like an
// attribute inside another attribute's quoted value is not an attribute.
func tagAttribute(tag, name string) (string, bool) {
	i := 1
	for i < len(tag) && !isHTMLSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	for i < len(tag) {
		for i < len(tag) && (isHTMLSpace(tag[i]) || tag[i] == '/') {
			i++
		}
		if i >= len(tag) || tag[i] == '>' {
			break
		}
		nameStart := i
		for i < len(tag) && !isHTMLSpace(tag[i]) && tag[i] != '=' && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		attr := strings.ToLower(tag[nameStart:i])
		for i < len(tag) && isHTMLSpace(tag[i]) {
			i++
		}
		value := ""
		if i < len(tag) && tag[i] == '=' {
			i++
			for i < len(tag) && isHTMLSpace(tag[i]) {
				i++
			}
			if i < len(tag) && (tag[i] == '"' || tag[i] == '\'') {
				q := tag[i]
				i++
				valueStart := i
				for i < len(tag) && tag[i] != q {
					i++
				}
				value = tag[valueStart:i]
				if i < len(tag) {
					i++
				}
			} else {
				valueStart := i
				for i < len(tag) && !isHTMLSpace(tag[i]) && tag[i] != '>' {
					i++
				}
				value = tag[valueStart:i]
			}
		}
		if attr == name {
			return value, true
		}
	}
	return "", false
}

// openingTag returns the real opening tag at the start of a match, or "" when
// the match does not start with a tag that closes.
func openingTag(match string) string {
	if end := tagEnd(match, 0); end > 0 {
		return match[:end]
	}
	return ""
}

// styleHides reports whether the tag's own style attribute hides it.
func styleHides(tag string) bool {
	style, ok := tagAttribute(tag, "style")
	return ok && hiddenCSSDeclRe.MatchString(style)
}

// ariaHiddenTrue reports whether the tag's own aria-hidden attribute is true.
func ariaHiddenTrue(tag string) bool {
	value, ok := tagAttribute(tag, "aria-hidden")
	return ok && strings.EqualFold(strings.TrimSpace(value), "true")
}

// replaceVerified removes each pattern match whose opening tag passes keep's
// attribute check and leaves the rest untouched. The patterns find
// candidates; the parsed tag decides, so attribute-like text inside another
// attribute's value cannot mark content hidden.
func replaceVerified(re *regexp.Regexp, s string, hidden func(tag string) bool) (string, int) {
	hits := 0
	out := re.ReplaceAllStringFunc(s, func(match string) string {
		if hidden(openingTag(match)) {
			hits++
			return ""
		}
		return match
	})
	if hits == 0 {
		return s, 0
	}
	return out, hits
}

// interfaceTags mark a hidden element as application interface rather than a
// trap: something a user interacts with or that lays out a view, which
// applications hide until their scripts reveal it. Wrapper and phrasing tags
// such as div, p, span, b and em do not count, because a trap can wrap its text
// in them as easily as an application can.
var interfaceTags = map[string]bool{
	"a": true, "article": true, "aside": true, "audio": true, "button": true,
	"canvas": true, "details": true, "dialog": true, "fieldset": true, "footer": true,
	"form": true, "header": true, "iframe": true, "img": true, "input": true,
	"label": true, "main": true, "nav": true, "ol": true, "option": true,
	"picture": true, "section": true, "select": true, "summary": true, "svg": true,
	"table": true, "template": true, "textarea": true, "ul": true, "video": true,
}

// hiddenTrapCandidate is one CSS-hidden div, span or p and where it closes.
type hiddenTrapCandidate struct {
	start, openEnd, closeStart, end int
	// opened is set when the tag scan reaches this opening tag. A pattern
	// match inside a comment, an attribute value, or script or style text is
	// never opened and is not an element.
	opened bool
}

// textSegment maps a run of document text, with tags removed, back to its
// offset in the original document.
type textSegment struct {
	orig, text, length int
}

// stripHiddenElementTraps removes each CSS-hidden div, span or p that holds no
// interface markup and whose text carries instruction vocabulary. The whole
// element is removed, from its opening tag to its matching close tag, so the
// rest of the document keeps its structure; an element with no matching close
// runs to the end of the document, as a browser would parse it. The text is
// read with tags removed, so inline markup cannot split a keyword apart.
//
// The work is linear in the document: one pass pairs every element with its
// close tag and records where interface tags and instruction words fall, and
// each candidate is then decided by lookup rather than by rescanning, so
// deeply nested hidden elements cannot make the rewrite quadratic.
func stripHiddenElementTraps(s string) (string, int) {
	lower := asciiLower(s)
	// Every hiding declaration names one of these properties, so a document
	// without them has no candidate and skips the scan.
	if !strings.Contains(lower, "display") && !strings.Contains(lower, "visibility") &&
		!strings.Contains(lower, "font-size") && !strings.Contains(lower, "opacity") {
		return s, 0
	}
	var candidates []hiddenTrapCandidate

	type openElement struct {
		tag       string
		candidate int
	}
	var stack []openElement
	openCount := map[string]int{}
	var interfacePos []int
	var text strings.Builder
	var segments []textSegment
	addText := func(from, to int) {
		if to <= from {
			return
		}
		segments = append(segments, textSegment{orig: from, text: text.Len(), length: to - from})
		text.WriteString(s[from:to])
	}

	pos := 0
	for pos < len(s) {
		lt := strings.IndexByte(s[pos:], '<')
		if lt < 0 {
			addText(pos, len(s))
			break
		}
		lt += pos
		addText(pos, lt)
		if strings.HasPrefix(s[lt:], "<!--") {
			closeComment := strings.Index(s[lt+4:], "-->")
			if closeComment < 0 {
				break
			}
			pos = lt + 4 + closeComment + 3
			continue
		}
		end := tagEnd(s, lt)
		if end < 0 {
			break
		}
		closing := lt+1 < len(s) && s[lt+1] == '/'
		nameStart := lt + 1
		if closing {
			nameStart++
		}
		nameEnd := nameStart
		for nameEnd < len(lower) && isTagNameByte(lower[nameEnd]) {
			nameEnd++
		}
		name := lower[nameStart:nameEnd]
		switch {
		case !closing && (name == "script" || name == "style"):
			// Script and style bodies are text to the browser, so markup
			// inside them opens no elements. Only a complete close tag ends
			// the body: </stylex> does not.
			pos = rawTextEnd(lower, end, name)
			continue
		case name == "div" || name == "span" || name == "p":
			if !closing {
				// The tag scan reads every opening tag quote-aware, so it
				// decides hiddenness from the real style attribute; no pattern
				// match can open or miss a candidate.
				candidate := -1
				if styleHides(s[lt:end]) {
					candidate = len(candidates)
					candidates = append(candidates, hiddenTrapCandidate{start: lt, openEnd: end, closeStart: len(s), end: len(s), opened: true})
				}
				stack = append(stack, openElement{tag: name, candidate: candidate})
				openCount[name]++
				break
			}
			if openCount[name] == 0 {
				// A stray closer has nothing to match; skipping it keeps the
				// pass linear however many unmatched closers a page carries.
				break
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag != name {
					continue
				}
				// Elements opened above the match never closed; they end where
				// their ancestor does.
				for j := len(stack) - 1; j > i; j-- {
					openCount[stack[j].tag]--
					if c := stack[j].candidate; c >= 0 {
						candidates[c].closeStart, candidates[c].end = lt, lt
					}
				}
				openCount[name]--
				if c := stack[i].candidate; c >= 0 {
					candidates[c].closeStart, candidates[c].end = lt, end
				}
				stack = stack[:i]
				break
			}
		case !closing && interfaceTags[name]:
			interfacePos = append(interfacePos, lt)
		}
		pos = end
	}

	body := text.String()
	words := trapInstructionRe.FindAllStringIndex(body, -1)
	textAt := func(orig int) int {
		i := sort.Search(len(segments), func(i int) bool { return segments[i].orig+segments[i].length > orig })
		if i == len(segments) {
			return len(body)
		}
		if orig <= segments[i].orig {
			return segments[i].text
		}
		return segments[i].text + orig - segments[i].orig
	}

	var b strings.Builder
	hits, written, removedUntil := 0, 0, 0
	for _, c := range candidates {
		if !c.opened || c.start < removedUntil {
			continue
		}
		// Interface markup anywhere inside keeps the element: applications hide
		// whole views, menus and forms until their scripts reveal them. Its text
		// is still read by response scanning.
		if k := sort.SearchInts(interfacePos, c.openEnd); k < len(interfacePos) && interfacePos[k] < c.closeStart {
			continue
		}
		lo, hi := textAt(c.openEnd), textAt(c.closeStart)
		k := sort.Search(len(words), func(i int) bool { return words[i][0] >= lo })
		if k == len(words) || words[k][1] > hi {
			continue
		}
		b.WriteString(s[written:c.start])
		written, removedUntil = c.end, c.end
		hits++
	}
	if hits == 0 {
		return s, 0
	}
	b.WriteString(s[written:])
	return b.String(), hits
}

// rawTextEnd returns the offset of the complete </name close tag that ends a
// script or style body starting at from, or len(lower) when there is none.
func rawTextEnd(lower string, from int, name string) int {
	closer := "</" + name
	for i := from; ; {
		k := strings.Index(lower[i:], closer)
		if k < 0 {
			return len(lower)
		}
		at := i + k
		next := at + len(closer)
		if next >= len(lower) || lower[next] == '>' || lower[next] == '/' || isHTMLSpace(lower[next]) {
			return at
		}
		i = next
	}
}

// isTagNameByte reports whether c can appear in a lowercase HTML tag name.
func isTagNameByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
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
