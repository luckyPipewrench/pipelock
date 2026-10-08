// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	mimeTrackerHost  = "tracker.vendor.example"
	mimePixelFixture = `<html><head></head><body><p>hello</p><img width="1" height="1" src="https://` + mimeTrackerHost + `/pixel.gif"></body></html>`
)

func contentTypeHeaders(values ...string) http.Header {
	headers := http.Header{}
	for _, value := range values {
		headers.Add("Content-Type", value)
	}
	return headers
}

// The expectations come from the Fetch standard's "extract a MIME type"
// examples and algorithm, not from the implementation.
func TestResponseMIMEType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"no header", nil, ""},
		{"single value is returned as written", []string{"text/html; charset=utf-8"}, "text/html; charset=utf-8"},
		{"two fields, last wins", []string{"text/plain", "text/html"}, "text/html"},
		{"one comma-combined field", []string{"text/plain, text/html"}, "text/html"},
		{"last wins even when it is the inert one", []string{"text/html", "text/plain"}, "text/plain"},
		{"charset reset when the essence differs", []string{"text/plain;charset=gbk, text/html"}, "text/html"},
		{"charset reset across fields", []string{"text/plain;charset=gbk", "text/html"}, "text/html"},
		{"charset carried across equal essences", []string{"text/html;charset=gbk, text/html"}, "text/html;charset=gbk"},
		{"charset carried across equal essences in separate fields", []string{"text/html;charset=gbk", "text/html"}, "text/html;charset=gbk"},
		{"later charset replaces an earlier one", []string{"text/html;charset=gbk, text/html;charset=utf-8"}, "text/html;charset=utf-8"},
		{"carry remembers first charset of essence", []string{"text/html;charset=utf-16le, text/html;charset=utf-8, text/html"}, "text/html;charset=utf-16le"},
		{"quoted semicolon does not declare charset", []string{`text/html;x=";charset=utf-16le", text/html`}, "text/html"},
		{"empty quoted charset overrides carry for winner", []string{`text/html;charset=utf-16le, text/html;charset=""`}, `text/html;charset=""`},
		{"empty quoted charset is carried", []string{`text/html;charset="", text/html`}, `text/html;charset=""`},
		{"unclosed quote spans header fields", []string{`text/plain;x="unterminated`, "text/html"}, `text/plain;x="unterminated, text/html`},
		{"carry is by essence, case-insensitive", []string{"text/html;charset=gbk, TEXT/HTML"}, "TEXT/HTML;charset=gbk"},
		{"invalid entry skipped", []string{"bogus, text/html"}, "text/html"},
		{"invalid trailing entry skipped", []string{"text/html", "bogus"}, "text/html"},
		{"wildcard skipped", []string{"text/html, */*"}, "text/html"},
		{"leading wildcard skipped", []string{"*/*", "text/html"}, "text/html"},
		{"comma inside a quoted parameter is not a split", []string{`text/plain; x="a, text/html"`}, `text/plain; x="a, text/html"`},
		{"quoted comma, then a real second value", []string{`text/plain; x="a, b", text/html`}, "text/html"},
		{"all invalid", []string{"bogus", "also bogus"}, ""},
		{"only a wildcard", []string{"*/*"}, ""},
		{"repeated equal values", []string{"text/html", "text/html", "text/html"}, "text/html"},
		{"parameters of an earlier essence do not leak", []string{"text/html;charset=gbk, text/plain, text/html"}, "text/html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := responseMIMEType(contentTypeHeaders(tc.values...)); got != tc.want {
				t.Fatalf("responseMIMEType(%q) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}

// With nothing to derive, classifiers keep reading the first raw value, so an
// empty or unparseable header is handled exactly as before.
func TestResponseContentTypeFallsBackToFirstValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"no header", nil, ""},
		{"unparseable", []string{"bogus"}, "bogus"},
		{"wildcard only", []string{"*/*"}, "*/*"},
		{"derived wins over the first value", []string{"text/plain", "text/html"}, "text/html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := responseContentType(contentTypeHeaders(tc.values...)); got != tc.want {
				t.Fatalf("responseContentType(%q) = %q, want %q", tc.values, got, tc.want)
			}
		})
	}
}

// Browser Shield must classify by the type the browser renders. Header.Get
// returns only the first value, so text/plain followed by text/html used to
// leave an HTML tracking pixel in place.
func TestBrowserShieldUsesBrowserVisibleContentType(t *testing.T) {
	cases := []struct {
		name       string
		values     []string
		wantShield bool
	}{
		{"text/plain then text/html, separate fields", []string{"text/plain", "text/html"}, true},
		{"text/plain then text/html, one field", []string{"text/plain, text/html"}, true},
		{"single text/html (positive control)", []string{"text/html"}, true},
		{"single text/plain (negative control)", []string{"text/plain"}, false},
		{"text/html then text/plain (browser renders text)", []string{"text/html", "text/plain"}, false},
	}
	for _, path := range []string{"forward", "tls interception", "reverse"} {
		for _, tc := range cases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				handler := svgResponseHandler(http.StatusOK, contentTypeHeaders(tc.values...), []byte(mimePixelFixture))
				got := runSVGPath(t, path, nil, handler)
				if !got.delivered {
					t.Fatalf("response refused: status=%d reason=%q", got.status, got.blockReason)
				}
				survived := strings.Contains(string(got.body), mimeTrackerHost)
				if tc.wantShield && survived {
					t.Fatalf("tracking pixel survived Browser Shield: %q", got.body)
				}
				if !tc.wantShield && !survived {
					t.Fatalf("body was rewritten although the browser renders it as text: %q", got.body)
				}
			})
		}
	}

	// The fetch endpoint returns extracted text for HTML and the raw body for
	// text, so the pixel's URL surviving is what distinguishes the two.
	for _, tc := range cases {
		t.Run("fetch/"+tc.name, func(t *testing.T) {
			handler := svgResponseHandler(http.StatusOK, contentTypeHeaders(tc.values...), []byte(mimePixelFixture))
			got := runSVGPath(t, "fetch", nil, handler)
			if !got.delivered {
				t.Fatalf("response refused: status=%d reason=%q", got.status, got.blockReason)
			}
			survived := strings.Contains(string(got.body), mimeTrackerHost)
			if tc.wantShield && survived {
				t.Fatalf("fetch treated an HTML response as plain text: %q", got.body)
			}
			if !tc.wantShield && !survived {
				t.Fatalf("fetch extracted a response the browser renders as text: %q", got.body)
			}
		})
	}
}

// applyShield reports a summary only when it rewrote something, and a rewrite
// of a response with several Content-Type values must not relabel it with the
// first one: the browser reads the last, so the delivered headers must still
// say HTML.
func TestApplyShieldSummaryAndRelabelForConflictingContentTypes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.BrowserShield.Enabled = true
	p := newTestProxyWithConfig(t, cfg)

	for _, tc := range []struct {
		name        string
		values      []string
		wantSummary bool
		wantType    string
	}{
		{"text/plain then text/html", []string{"text/plain", "text/html"}, true, "text/html"},
		{"text/plain;charset=gbk then text/html", []string{"text/plain;charset=gbk", "text/html"}, true, "text/html"},
		{"single text/html", []string{"text/html"}, true, "text/html"},
		{"single text/plain", []string{"text/plain"}, false, "text/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := contentTypeHeaders(tc.values...)
			body, summary, _, blocked := p.applyShield([]byte(mimePixelFixture), responseContentType(headers), "example.com", headers, cfg, audit.LogContext{}, "127.0.0.1", "req", TransportFetch, "action")
			if blocked != nil {
				t.Fatalf("unexpected block: %v", blocked.reason)
			}
			if (summary != nil) != tc.wantSummary {
				t.Fatalf("summary = %+v, want non-nil=%t", summary, tc.wantSummary)
			}
			if tc.wantSummary && strings.Contains(string(body), mimeTrackerHost) {
				t.Fatalf("tracking pixel survived: %q", body)
			}
			if got := headers.Values("Content-Type"); len(got) != 1 || got[0] != tc.wantType {
				t.Fatalf("delivered Content-Type = %q, want [%s]", got, tc.wantType)
			}
		})
	}
}

// Media policy classifies by the same type. An allowed first value must not
// hide a denied media type the browser will actually use.
func TestMediaPolicyUsesLastValidContentType(t *testing.T) {
	// A plausible MP3 frame header; the type decision here comes from the
	// declared type, and the body is only ever delivered or refused.
	body := []byte("opaque-bytes-no-media-signature")
	cases := []struct {
		name        string
		values      []string
		wantRefused bool
	}{
		{"text/plain then audio/mpeg", []string{"text/plain", "audio/mpeg"}, true},
		{"text/plain, audio/mpeg in one field", []string{"text/plain, audio/mpeg"}, true},
		{"single audio/mpeg (positive control)", []string{"audio/mpeg"}, true},
		{"single text/plain (negative control)", []string{"text/plain"}, false},
		{"audio/mpeg then text/plain (browser renders text)", []string{"audio/mpeg", "text/plain"}, false},
	}
	for _, path := range []string{"forward", "tls interception", "reverse"} {
		for _, tc := range cases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				handler := svgResponseHandler(http.StatusOK, contentTypeHeaders(tc.values...), body)
				got := runSVGPath(t, path, nil, handler)
				if tc.wantRefused {
					if got.delivered || got.blockReason != "media_policy: audio stripped" {
						t.Fatalf("audio not refused: status=%d reason=%q body=%q", got.status, got.blockReason, got.body)
					}
					return
				}
				if !got.delivered || string(got.body) != string(body) {
					t.Fatalf("response not delivered intact: status=%d reason=%q body=%q", got.status, got.blockReason, got.body)
				}
			})
		}
	}
}

// A carried charset is appended to the winning entry as text. When that entry
// is malformed the appended parameter must still be seen, and a carried UTF-16
// charset must still make the decoder refuse rather than read the body as
// something else.
func TestResponseMIMETypeCarriedCharsetSurvivesMalformedWinner(t *testing.T) {
	t.Parallel()
	for _, winner := range []string{"text/html;", `text/html; x="unterminated`, "text/html; =bad"} {
		t.Run(winner, func(t *testing.T) {
			t.Parallel()
			derived := responseMIMEType(contentTypeHeaders("text/html;charset=utf-16le, " + winner))
			declared, _ := shieldDeclaredCharset(derived)
			if declared != "utf-16le" {
				t.Fatalf("derived %q declares charset %q, want the carried utf-16le", derived, declared)
			}
			if _, utf16, err := decodeShieldUTF16([]byte("<\x00h\x00"), derived, 0); err == nil && !utf16 {
				t.Fatalf("carried UTF-16 charset ignored for %q", derived)
			}
		})
	}
}
