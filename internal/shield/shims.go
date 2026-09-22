// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"regexp"
	"strings"
)

// ExtensionProbeShim hooks fetch() and XMLHttpRequest.open() to block
// chrome-extension:// and moz-extension:// URL access at runtime.
// Injected as a <script> tag immediately after <head> when
// strip_extension_probing is enabled.
const ExtensionProbeShim = `(function(){` +
	`if(typeof window!=='undefined'&&typeof window.fetch==='function'){` +
	`var _fetch=window.fetch;` +
	`window.fetch=function(input,init){` +
	`var url=(typeof input==='string')?input:(input instanceof Request)?input.url:'';` +
	`if(/^(chrome|moz)-extension:\/\//i.test(url)){return Promise.reject(new TypeError('Network request failed'));}` +
	`return _fetch.apply(this,arguments);` +
	`};` +
	`}` +
	`if(typeof XMLHttpRequest!=='undefined'){` +
	`var _xhrOpen=XMLHttpRequest.prototype.open;` +
	`XMLHttpRequest.prototype.open=function(method,url){` +
	`if(typeof url==='string'&&/^(chrome|moz)-extension:\/\//i.test(url)){throw new DOMException('Blocked','NetworkError');}` +
	`return _xhrOpen.apply(this,arguments);` +
	`};` +
	`}` +
	`})();`

// FingerprintShim overrides canvas, WebGL, and audio fingerprinting APIs.
// Returns neutral values that prevent cross-session fingerprint correlation
// without breaking legitimate canvas/WebGL rendering.
const FingerprintShim = `(function(){` +
	`if(typeof HTMLCanvasElement!=='undefined'){` +
	`var _toDataURL=HTMLCanvasElement.prototype.toDataURL;` +
	`HTMLCanvasElement.prototype.toDataURL=function(){` +
	`if(this.width<=300&&this.height<=150){return 'data:image/png;base64,iVBORw0KGgo=';}` +
	`return _toDataURL.apply(this,arguments);` +
	`};` +
	`}` +
	`if(typeof WebGLRenderingContext!=='undefined'){` +
	`var _getParam=WebGLRenderingContext.prototype.getParameter;` +
	`WebGLRenderingContext.prototype.getParameter=function(p){` +
	`if(p===37445)return 'Generic Renderer';` +
	`if(p===37446)return 'Generic Vendor';` +
	`return _getParam.apply(this,arguments);` +
	`};` +
	`var _getExt=WebGLRenderingContext.prototype.getExtension;` +
	`WebGLRenderingContext.prototype.getExtension=function(name){` +
	`if(name==='WEBGL_debug_renderer_info')return null;` +
	`return _getExt.apply(this,arguments);` +
	`};` +
	`}` +
	`if(typeof navigator!=='undefined'&&navigator.sendBeacon){` +
	`navigator.sendBeacon=function(){return false;};` +
	`}` +
	`})();`

// nonceRe extracts the nonce attribute from the first <script nonce="..."> tag.
var nonceRe = regexp.MustCompile(`(?i)<script[^>]+nonce\s*=\s*["']([^"']+)["']`)

// safeNonce reports whether a nonce can be written into an attribute without
// changing the structure of the markup around it. A CSP nonce is a base64
// token, so anything outside that alphabet is not a nonce worth echoing. The
// character that matters is `>`: buildShimBlockXML finds the end of the start
// tag by looking for the first one, so a nonce carrying `>` moves that boundary
// into the middle of the attribute value and the CDATA guard lands inside the
// quotes. The document then stops parsing as XML and the browser refuses to
// render it, an availability failure caused by echoing upstream input.
var safeNonce = regexp.MustCompile(`^[A-Za-z0-9+/\-_=]+$`)

// buildShimBlock returns a <script> tag wrapping the given shim code.
// If a CSP nonce is present in the document, it is applied to the tag so the
// browser does not reject the injected script.
func buildShimBlock(shims []string, doc string) string {
	return buildShimBlockWithNonce(shims, doc, "")
}

// buildShimBlockWithNonce returns a <script> tag wrapping shim code.
// headerNonce (from CSP response header) takes precedence over body-extracted
// nonce. This ensures shims work on pages where the CSP nonce is only in the
// header, not duplicated in existing <script> tags.
func buildShimBlockWithNonce(shims []string, doc, headerNonce string) string {
	if len(shims) == 0 {
		return ""
	}
	code := strings.Join(shims, "\n")

	// An unusable nonce is dropped rather than echoed. Losing the attribute
	// means the browser's own CSP refuses the injected shim, which costs one
	// hardening layer on that single response; writing it through unchecked
	// breaks the whole document instead.
	var nonceAttr string
	if headerNonce != "" && safeNonce.MatchString(headerNonce) {
		nonceAttr = ` nonce="` + headerNonce + `"`
	} else if m := nonceRe.FindStringSubmatch(doc); len(m) > 1 && safeNonce.MatchString(m[1]) {
		nonceAttr = ` nonce="` + m[1] + `"`
	}

	return "<script" + nonceAttr + ">" + code + "</script>"
}

// buildShimBlockXML wraps the injected JavaScript in a CDATA section. An XHTML
// document is parsed as XML, where a raw `&` or `<` inside a script element is
// not well-formed and makes the whole page fail to render. The shim code
// contains both (`&&`, and comparisons), so injecting the HTML form into XHTML
// breaks the document the shield is supposed to be protecting. The `//` guards
// keep the CDATA delimiters from being read as JavaScript by any parser that
// treats the element as HTML instead.
func buildShimBlockXML(shims []string, doc, headerNonce string) string {
	block := buildShimBlockWithNonce(shims, doc, headerNonce)
	if block == "" {
		return ""
	}
	open := strings.Index(block, ">")
	closeTag := strings.LastIndex(block, "</script>")
	if open < 0 || closeTag < 0 || closeTag <= open {
		return block
	}
	code := block[open+1 : closeTag]
	return block[:open+1] + "//<![CDATA[\n" + code + "\n//]]>" + block[closeTag:]
}

// headRe matches the first <head...> tag in the document.
var headRe = regexp.MustCompile(`(?i)<head[^>]*>`)

// htmlRe matches the first <html...> tag (fallback when <head> is absent).
var htmlRe = regexp.MustCompile(`(?i)<html[^>]*>`)

// injectShim inserts a script block after the best injection point:
// <head>, then <html>, then prepend.
func injectShim(doc, block string) string {
	if loc := headRe.FindStringIndex(doc); loc != nil {
		return doc[:loc[1]] + block + doc[loc[1]:]
	}
	if loc := htmlRe.FindStringIndex(doc); loc != nil {
		return doc[:loc[1]] + block + doc[loc[1]:]
	}
	// No structural tag found; prepend.
	return block + doc
}
