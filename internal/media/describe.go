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
