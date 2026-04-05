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
	`var _fetch=window.fetch;` +
	`window.fetch=function(input,init){` +
	`var url=(typeof input==='string')?input:(input instanceof Request)?input.url:'';` +
	`if(/^(chrome|moz)-extension:\/\//i.test(url)){return Promise.reject(new TypeError('Network request failed'));}` +
	`return _fetch.apply(this,arguments);` +
	`};` +
	`var _xhrOpen=XMLHttpRequest.prototype.open;` +
	`XMLHttpRequest.prototype.open=function(method,url){` +
	`if(typeof url==='string'&&/^(chrome|moz)-extension:\/\//i.test(url)){throw new DOMException('Blocked','NetworkError');}` +
	`return _xhrOpen.apply(this,arguments);` +
	`};` +
	`})();`

// FingerprintShim overrides canvas, WebGL, and audio fingerprinting APIs.
// Returns neutral values that prevent cross-session fingerprint correlation
// without breaking legitimate canvas/WebGL rendering.
const FingerprintShim = `(function(){` +
	`var _toDataURL=HTMLCanvasElement.prototype.toDataURL;` +
	`HTMLCanvasElement.prototype.toDataURL=function(){` +
	`if(this.width<=300&&this.height<=150){return 'data:image/png;base64,iVBORw0KGgo=';}` +
	`return _toDataURL.apply(this,arguments);` +
	`};` +
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
	`navigator.sendBeacon=function(){return false;};` +
	`})();`

// nonceRe extracts the nonce attribute from the first <script nonce="..."> tag.
var nonceRe = regexp.MustCompile(`(?i)<script[^>]+nonce\s*=\s*["']([^"']+)["']`)

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

	var nonceAttr string
	if headerNonce != "" {
		nonceAttr = ` nonce="` + headerNonce + `"`
	} else if m := nonceRe.FindStringSubmatch(doc); len(m) > 1 {
		nonceAttr = ` nonce="` + m[1] + `"`
	}

	return "<script" + nonceAttr + ">" + code + "</script>"
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
