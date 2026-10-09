// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMediaContentType(t *testing.T) {
	t.Parallel()
	for _, mt := range []string{
		"image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/x-icon", "image/svg+xml",
		"audio/mpeg", "audio/wav", "audio/wave", "audio/ogg", "audio/aiff", "audio/midi", "audio/basic",
		"video/mp4", "video/webm", "video/avi",
		"image/unknown", "audio/unknown", "video/unknown", "unknown",
	} {
		t.Run(mt, func(t *testing.T) {
			if got := MediaContentType(mt); got != mt {
				t.Fatalf("media type=%q, want %q", got, mt)
			}
		})
	}
	for _, tt := range []struct{ in, want string }{
		{"image/custom", "image/unknown"},
		{"audio/custom", "audio/unknown"},
		{"video/custom", "video/unknown"},
		{"", "unknown"},
		{"application/custom", "unknown"},
	} {
		if got := MediaContentType(tt.in); got != tt.want {
			t.Fatalf("media type=%q, want %q", got, tt.want)
		}
	}
}

func TestLogMediaExposureProjectsUntrustedType(t *testing.T) {
	t.Parallel()
	const secret = "private-sensitive-value-73519"
	var output bytes.Buffer
	logger, err := NewWithStream("json", "stdout", "", true, true, &output)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogMediaExposure(LogContext{}, MediaExposureInfo{Transport: "mcp", ContentType: "image/" + secret})
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["content_type"] != "image/unknown" || strings.Contains(output.String(), secret) {
		t.Fatal("media exposure retained upstream content type")
	}
}
