// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMediaExposureContentTypeRecognizedTypes(t *testing.T) {
	t.Parallel()
	for _, mt := range []string{"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/x-icon", svgMediaType, "audio/mpeg", "audio/wav", "audio/ogg", "video/mp4", "video/webm"} {
		t.Run(mt, func(t *testing.T) {
			if got := audit.MediaContentType(mt); got != mt {
				t.Fatalf("content type=%q, want %q", got, mt)
			}
		})
	}
	if got := audit.MediaContentType("application/custom"); got != "unknown" {
		t.Fatalf("non-media content type=%q, want unknown", got)
	}
}

func TestMediaExposureOutputProjectsDirectlyBuiltFields(t *testing.T) {
	t.Parallel()
	const secret = "private-sensitive-value-73519"
	for _, tt := range []struct{ in, want string }{
		{"image/" + secret, "image/unknown"},
		{"audio/" + secret, "audio/unknown"},
		{"video/" + secret, "video/unknown"},
		{"audio/wave", "audio/wave"},
		{"image/unknown", "image/unknown"},
	} {
		fields := &MediaExposureFields{ContentType: tt.in}
		if got := fields.ToAuditInfo("reverse").ContentType; got != tt.want {
			t.Fatalf("audit content type=%q, want %q", got, tt.want)
		}
		if got := fields.ToEventFields()["content_type"]; got != tt.want {
			t.Fatalf("event content type=%v, want %q", got, tt.want)
		}
	}
}

func TestMediaExposureDoesNotRetainHeaderSecrets(t *testing.T) {
	t.Parallel()
	const secret = "private-sensitive-value-73519"
	for _, tt := range []struct{ name, header, want string }{
		{"image subtype", "image/" + secret, "image/unknown"},
		{"audio subtype", "audio/" + secret, "audio/unknown"},
		{"video subtype", "video/" + secret, "video/unknown"},
		{"malformed subtype", "image/" + secret + " malformed", "image/unknown"},
		{"valid parameter", "image/png; secret=" + secret, "image/png"},
		{"malformed parameter", "image/png; secret=\"" + secret, "image/png"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Defaults()
			headers := http.Header{"Content-Type": {tt.header}}
			verdict := applyMediaPolicy(cfg, responseContentType(headers), nil)
			if verdict.Exposure == nil {
				t.Fatal("missing exposure")
			}
			if verdict.Exposure.ContentType != tt.want {
				t.Fatalf("content type=%q, want %q", verdict.Exposure.ContentType, tt.want)
			}
			if strings.Contains(verdict.BlockReason, secret) {
				t.Fatal("header secret retained in block reason")
			}
			for _, transport := range []string{"fetch", "forward", "connect", "reverse"} {
				logger := &fakeMediaLogger{}
				logMediaExposureIfPresent(logger, audit.LogContext{}, verdict, transport)
				data, err := json.Marshal([]any{logger.calls, verdict.Exposure.ToEventFields()})
				if err != nil {
					t.Fatal(err)
				}
				if len(logger.calls) != 1 || strings.Contains(string(data), secret) {
					t.Fatalf("%s: exposure leaked header or was not logged", transport)
				}
				var output bytes.Buffer
				realLogger, err := audit.NewWithStream("json", "stdout", "", true, true, &output)
				if err != nil {
					t.Fatal(err)
				}
				logMediaExposureIfPresent(realLogger, audit.LogContext{}, verdict, transport)
				if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), tt.want) {
					t.Fatalf("%s: audit output leaked header or lost media classification", transport)
				}
			}
		})
	}
}
