// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package media

import (
	"net/http"
	"strings"
)

// DescribeBytes names what a response body actually is, using the WHATWG MIME
// sniffing algorithm that net/http implements. It lets a type-mismatch block
// say what the upstream sent (for example image/webp or text/html) instead of
// only that the declared type was wrong. It returns just the media type,
// without parameters.
func DescribeBytes(body []byte) string {
	if len(body) == 0 {
		return "empty"
	}
	sniffed := http.DetectContentType(body)
	if i := strings.IndexByte(sniffed, ';'); i >= 0 {
		sniffed = sniffed[:i]
	}
	return strings.TrimSpace(sniffed)
}

// strippedRasterTypes are the declared types StripMetadata parses by
// signature. A body declared as one of these but carrying another format
// fails that parse.
var strippedRasterTypes = map[string]bool{"image/jpeg": true, "image/jpg": true, "image/pjpeg": true, "image/png": true}

// sniffableRasterTypes are the formats DetectType validates by their full
// container header, not a short prefix. ICO is excluded because its
// signature is four bytes that arbitrary data can start with.
var sniffableRasterTypes = map[string]bool{"image/jpeg": true, "image/png": true, "image/gif": true, "image/webp": true, "image/bmp": true}

// StripType returns the media type to strip a body as. Some CDNs serve a
// WebP or GIF body under a JPEG or PNG Content-Type; browsers render it from
// the bytes, but parsing it as the declared format fails its signature check.
// When the declared type is one StripMetadata parses and the bytes are
// recognizably a different raster format the operator allows, the body is
// handled as the format its bytes prove. Anything else, including SVG, HTML
// and unrecognized bytes, keeps the declared type so the signature check
// still refuses it.
func StripType(declared string, body []byte, allowed func(string) bool) string {
	mt := canonicalMediaType(declared)
	if !strippedRasterTypes[mt] {
		return declared
	}
	// DetectType checks each format's whole header, where the WHATWG sniffer
	// behind DescribeBytes accepts short prefixes such as "BM" or "GIF89a"
	// that any payload can begin with. A relabeled body is therefore treated
	// exactly like an honestly labeled one of the proven type, never looser.
	sniffed := DetectType(body)
	if sniffed == mt || !sniffableRasterTypes[sniffed] || allowed == nil || !allowed(sniffed) {
		return declared
	}
	if (mt == "image/jpg" || mt == "image/pjpeg") && sniffed == "image/jpeg" {
		return declared
	}
	return sniffed
}
