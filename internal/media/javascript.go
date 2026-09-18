// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

// JavaScriptMediaTypes is the RFC 9239 section 6 list of JavaScript media
// types: the current registration ("text/javascript") plus every historical
// alias the RFC documents as equivalent for processing purposes.
//
// This table is shared by two consumers that must never drift apart: the
// browser shield's response-pipeline classifier (internal/shield) picks the
// JS rewrite pipeline from it, and the unscannable-passthrough classifier
// (internal/config, used again at request time by internal/proxy) refuses an
// opaque-download exception for anything on this list, because an exempted
// alias would let an equivalent JavaScript response skip both the shield and
// response-body scanning. A table edited in only one of those two places is
// exactly the drift this file exists to prevent; see the parity test in
// internal/shield and internal/config for the mechanical check.
var JavaScriptMediaTypes = []string{
	"text/javascript",
	"application/javascript",
	"application/x-javascript",
	"text/javascript1.0",
	"text/javascript1.1",
	"text/javascript1.2",
	"text/javascript1.3",
	"text/javascript1.4",
	"text/javascript1.5",
	"text/jscript",
	"text/livescript",
	"text/ecmascript",
	"application/ecmascript",
	"application/x-ecmascript",
	"text/x-ecmascript",
	"text/x-javascript",
}

var javaScriptMediaTypeSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(JavaScriptMediaTypes))
	for _, mt := range JavaScriptMediaTypes {
		set[mt] = struct{}{}
	}
	return set
}()

// IsJavaScriptMediaType reports whether mt (already lowercased, with any
// parameters stripped, per mime.ParseMediaType) is one of the RFC 9239
// section 6 JavaScript media types.
func IsJavaScriptMediaType(mt string) bool {
	_, ok := javaScriptMediaTypeSet[mt]
	return ok
}
