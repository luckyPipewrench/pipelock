// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
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
// keywords. The value may be quoted or bare, as HTML allows; ariaHiddenTrue
// then decides from the parsed attribute.
const ariaHiddenTrapPattern = `(?i)<[^>]*\saria-hidden\s*=\s*["']?true\b["']?[^>]*>[^<]*(?:ignore|disregard|forget|override|instead|instruction)[^<]*</[^>]+>`

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

// startTagAttr reads the named attribute of the first tag in markup with the
// HTML tokenizer, so quoting, character references and attribute-like text
// inside another value are read the way a browser reads them. Like a browser,
// it takes the first of duplicated attributes.
func startTagAttr(markup, name string) (string, bool) {
	z := html.NewTokenizer(strings.NewReader(markup))
	switch z.Next() {
	case html.StartTagToken, html.SelfClosingTagToken:
	default:
		return "", false
	}
	_, more := z.TagName()
	for more {
		var key, value []byte
		key, value, more = z.TagAttr()
		if string(key) == name {
			return string(value), true
		}
	}
	return "", false
}

// styleHides reports whether the first tag's own style attribute hides it.
func styleHides(tag string) bool {
	style, ok := startTagAttr(tag, "style")
	return ok && styleValueHides(style)
}

// styleValueHides resolves each hiding property the way a browser does: a
// later declaration overrides an earlier one unless the earlier one is
// !important and the later is not.
func styleValueHides(style string) bool {
	type effective struct {
		value     string
		important bool
		set       bool
	}
	props := map[string]*effective{"display": {}, "visibility": {}, "font-size": {}, "opacity": {}}
	for _, decl := range cssDeclarations(style) {
		name, value := decl.name, decl.value
		prop := props[strings.ToLower(strings.TrimSpace(name))]
		if prop == nil {
			continue
		}
		value = strings.ToLower(strings.TrimSpace(value))
		important := decl.important
		if prop.set && prop.important && !important {
			continue
		}
		*prop = effective{value: value, important: important, set: true}
	}
	for name, prop := range props {
		if prop.set && hiddenCSSDeclRe.MatchString(name+":"+prop.value) {
			return true
		}
	}
	return false
}

// ariaHiddenTrue reports whether the first tag's own aria-hidden is true.
func ariaHiddenTrue(tag string) bool {
	value, ok := startTagAttr(tag, "aria-hidden")
	return ok && strings.EqualFold(strings.TrimSpace(value), "true")
}

// replaceVerified removes each pattern match whose first tag passes hidden's
// attribute check and leaves the rest untouched. The patterns find
// candidates; the tokenized tag decides, so attribute-like text inside
// another attribute's value cannot mark content hidden.
func replaceVerified(re *regexp.Regexp, s string, hidden func(tag string) bool) (string, int) {
	hits := 0
	out := re.ReplaceAllStringFunc(s, func(match string) string {
		if hidden(match) {
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

// rawTextElements are the elements whose body the tokenizer returns as one
// text token; that body is not page text a reader sees.
var rawTextElements = map[string]bool{
	"iframe": true, "noembed": true, "noframes": true, "noscript": true, "plaintext": true,
	"script": true, "style": true, "textarea": true, "title": true, "xmp": true,
}

// closesParagraph lists the opening tags that implicitly close an open p
// element under the HTML parsing rules.
var closesParagraph = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "details": true,
	"dialog": true, "div": true, "dl": true, "fieldset": true, "figcaption": true,
	"figure": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true,
	"h4": true, "h5": true, "h6": true, "header": true, "hgroup": true, "hr": true,
	"main": true, "menu": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "summary": true, "table": true, "ul": true,
}

// hiddenTrapCandidate is one CSS-hidden div, span or p and where it closes.
type hiddenTrapCandidate struct {
	start, openEnd, closeStart, end int
}

// stripHiddenElementTraps removes each CSS-hidden or aria-hidden div, span or p whose text
// carries instruction vocabulary. An element with no interface markup is
// removed whole; one with interface markup keeps its markup and loses only the
// text that carries the instruction words. A removed element goes from its
// opening tag to its matching close tag, so the rest of the document keeps its
// structure; an element with no matching close runs to the end of the
// document, as a browser would parse it.
//
// The document is read with the HTML tokenizer, so quoting, character
// references, comments and raw-text element bodies follow the HTML rules, and
// text is read unescaped with tags removed so markup cannot split a keyword.
// Each candidate is decided by lookup after one pass, so nested or stray tags
// cannot make the rewrite quadratic. xml selects XHTML and SVG parsing, where a
// self-closing tag ends its element.
func stripHiddenElementTraps(s string, xml bool) (string, int) {
	// Every candidate carries a style or aria-hidden attribute, and an
	// attribute name cannot be written with character references.
	if lower := asciiLower(s); !strings.Contains(lower, "style") && !strings.Contains(lower, "aria-hidden") {
		return s, 0
	}
	type openElement struct {
		tag       string
		candidate int
	}
	type boundary struct {
		orig, text int
	}
	var (
		candidates   []hiddenTrapCandidate
		stack        []openElement
		interfacePos []int
		bounds       []boundary
		textTokens   []textToken
		text         strings.Builder
	)
	openCount := map[string]int{}
	closeOpen := func(from, at, end int, closeAll bool) {
		// Ends the stack entries from index from upward. Entries above from
		// never closed: they end where the closing tag starts.
		for j := len(stack) - 1; j >= from; j-- {
			openCount[stack[j].tag]--
			if c := stack[j].candidate; c >= 0 {
				candidates[c].closeStart, candidates[c].end = at, at
				if j == from && !closeAll {
					candidates[c].end = end
				}
			}
		}
		stack = stack[:from]
	}
	openAt := func(tag string, start, end int, raw []byte) {
		candidate := -1
		// aria-hidden div, span and p elements are decided here too, so their
		// text is read decoded and tag-free like any other hidden element.
		// Other aria-hidden tags stay with the pattern pass in stripTraps.
		if tag := string(raw); styleHides(tag) || ariaHiddenTrue(tag) {
			candidate = len(candidates)
			candidates = append(candidates, hiddenTrapCandidate{start: start, openEnd: end, closeStart: len(s), end: len(s)})
		}
		stack = append(stack, openElement{tag: tag, candidate: candidate})
		openCount[tag]++
	}

	z := html.NewTokenizer(strings.NewReader(s))
	off := 0
	rawBody := false
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		start := off
		off += len(z.Raw())
		bounds = append(bounds, boundary{orig: start, text: text.Len()})
		if tt == html.TextToken {
			if !rawBody {
				t0 := text.Len()
				text.Write(z.Text())
				textTokens = append(textTokens, textToken{orig: start, origEnd: off, text: t0, textEnd: text.Len()})
			}
			rawBody = false
			continue
		}
		rawBody = false
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken && tt != html.EndTagToken {
			continue
		}
		raw := z.Raw()
		nameBytes, _ := z.TagName()
		name := string(nameBytes)
		if tt == html.EndTagToken {
			if (name == "div" || name == "span" || name == "p") && openCount[name] > 0 {
				for i := len(stack) - 1; i >= 0; i-- {
					if stack[i].tag == name {
						closeOpen(i, start, off, false)
						break
					}
				}
			}
			continue
		}
		if openCount["p"] > 0 && closesParagraph[name] {
			// An opening block element closes the open p before it, so a
			// hidden p ends here rather than swallowing what follows.
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].tag == "p" {
					closeOpen(i, start, start, true)
					break
				}
			}
		}
		if interfaceTags[name] {
			interfacePos = append(interfacePos, start)
		}
		// HTML ignores a self-closing slash on these elements, so <script/>
		// still starts a raw-text body. XHTML and SVG are XML, where the slash
		// ends the element and the text after it is ordinary markup.
		if rawTextElements[name] {
			if xml && tt == html.SelfClosingTagToken {
				z.NextIsNotRawText()
			} else {
				rawBody = true
			}
		}
		// HTML ignores a self-closing slash on div, span or p, so both token
		// kinds open the element. In XHTML and SVG the slash ends it at once,
		// so it holds nothing and the text after it is outside.
		if (name == "div" || name == "span" || name == "p") && (!xml || tt != html.SelfClosingTagToken) {
			openAt(name, start, off, raw)
		}
	}
	bounds = append(bounds, boundary{orig: off, text: text.Len()})

	body := text.String()
	words := trapInstructionRe.FindAllStringIndex(body, -1)
	textAt := func(orig int) int {
		i := sort.Search(len(bounds), func(i int) bool { return bounds[i].orig >= orig })
		if i == len(bounds) {
			return len(body)
		}
		return bounds[i].text
	}

	hasWord := func(lo, hi int) (int, bool) {
		k := sort.Search(len(words), func(i int) bool { return words[i][0] >= lo })
		return k, k < len(words) && words[k][1] <= hi
	}
	hasInterface := func(c hiddenTrapCandidate) bool {
		j := sort.SearchInts(interfacePos, c.openEnd)
		return j < len(interfacePos) && interfacePos[j] < c.closeStart
	}

	// Pass 1: hidden elements with no interface markup and an instruction
	// word are removed whole.
	var cuts [][2]int
	var removedText [][2]int
	hits, removedUntil := 0, 0
	for _, c := range candidates {
		if c.start < removedUntil || hasInterface(c) {
			continue
		}
		if _, ok := hasWord(textAt(c.openEnd), textAt(c.closeStart)); !ok {
			continue
		}
		cuts = append(cuts, [2]int{c.start, c.end})
		removedText = append(removedText, [2]int{textAt(c.start), textAt(c.end)})
		removedUntil = c.end
		hits++
	}
	inRemoved := func(w []int) bool {
		i := sort.Search(len(removedText), func(i int) bool { return removedText[i][1] > w[0] })
		return i < len(removedText) && removedText[i][0] <= w[0]
	}
	insideCut := func(pos int) bool {
		i := sort.Search(len(cuts), func(i int) bool { return cuts[i][1] > pos })
		return i < len(cuts) && cuts[i][0] <= pos
	}

	// Pass 2: interface markup keeps the element, because applications hide
	// whole views, menus and forms until their scripts reveal them. The
	// instruction-bearing text inside it is still removed, so an empty button
	// cannot carry a trap past the shield. The text is removed a whole text
	// node at a time: cutting only the matched word would leave the rest of
	// the instruction for the agent to read.
	//
	// Nested hidden elements share their words, so each candidate only records
	// its text span here and every word is then visited once, however deeply
	// the elements nest.
	live := make([][]int, 0, len(words))
	for _, w := range words {
		if !inRemoved(w) {
			live = append(live, w)
		}
	}
	var spans [][2]int
	for _, c := range candidates {
		if !hasInterface(c) || insideCut(c.start) {
			continue
		}
		lo, hi := textAt(c.openEnd), textAt(c.closeStart)
		k := sort.Search(len(live), func(i int) bool { return live[i][0] >= lo })
		if k < len(live) && live[k][1] <= hi {
			spans = append(spans, [2]int{lo, hi})
			hits++
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	next, reach := 0, -1
	var last [2]int
	for _, w := range live {
		// reach is the furthest end of any span that starts at or before w,
		// so w lies inside some span exactly when it ends by reach.
		for ; next < len(spans) && spans[next][0] <= w[0]; next++ {
			reach = max(reach, spans[next][1])
		}
		if w[1] > reach {
			continue
		}
		for _, cut := range textCuts(textTokens, w[0], w[1]) {
			if cut != last {
				cuts = append(cuts, cut)
				last = cut
			}
		}
	}
	if hits == 0 {
		return s, 0
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i][0] < cuts[j][0] })
	var b strings.Builder
	written := 0
	for _, cut := range cuts {
		if cut[1] <= written {
			continue
		}
		if cut[0] > written {
			b.WriteString(s[written:cut[0]])
		}
		written = cut[1]
	}
	b.WriteString(s[written:])
	return b.String(), hits
}

// textToken locates one run of document text both in the original bytes and
// in the decoded, tag-free text the instruction words are matched against.
type textToken struct {
	orig, origEnd, text, textEnd int
}

// textCuts returns the original byte range of every text token that overlaps
// the decoded text range [from, to). A keyword split across inline tags spans
// several tokens, and each of them is removed.
func textCuts(tokens []textToken, from, to int) [][2]int {
	var cuts [][2]int
	i := sort.Search(len(tokens), func(i int) bool { return tokens[i].textEnd > from })
	for ; i < len(tokens) && tokens[i].text < to; i++ {
		cuts = append(cuts, [2]int{tokens[i].orig, tokens[i].origEnd})
	}
	return cuts
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
