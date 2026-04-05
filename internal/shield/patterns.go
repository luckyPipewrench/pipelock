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

// trackingPixelPattern matches 1x1 image tags (width/height in either order).
const trackingPixelPattern = `(?i)<img[^>]+(?:width\s*=\s*["']?1["']?\s+height\s*=\s*["']?1["']?|height\s*=\s*["']?1["']?\s+width\s*=\s*["']?1["']?)[^>]*>`

// sendBeaconPattern matches navigator.sendBeacon() calls.
const sendBeaconPattern = `(?i)navigator\.sendBeacon\s*\(`

// prefetchPattern matches <link rel="prefetch"> tags.
const prefetchPattern = `(?i)<link[^>]+rel\s*=\s*["']?prefetch["']?[^>]*>`

// Hidden trap patterns.

// commentTrapPattern matches HTML comments containing instruction-like keywords
// that could be prompt injections hidden from rendering.
const commentTrapPattern = `<!--[\s\S]*?(?:ignore|disregard|forget|override|instead|instruction)[\s\S]*?-->`

// hiddenElementPattern matches elements hidden via CSS that could contain
// injected instructions invisible to the user but visible to an AI agent
// reading the DOM.
const hiddenElementPattern = `(?i)<(?:div|span|p)[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden)[^"']*["'][^>]*>[\s\S]*?</(?:div|span|p)>`

// ariaHiddenTrapPattern matches aria-hidden elements containing instruction
// keywords.
const ariaHiddenTrapPattern = `(?i)<[^>]+aria-hidden\s*=\s*["']true["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|instruction)[^<]*</[^>]+>`

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
