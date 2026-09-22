// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/media"
)

// rfc9239JavaScriptMediaTypes is intentionally written independently from
// media.JavaScriptMediaTypes. RFC 9239 section 6 defines these registrations
// as JavaScript aliases.
var rfc9239JavaScriptMediaTypes = []string{
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

func TestJavaScriptMediaTypesMatchRFC9239Section6(t *testing.T) {
	want := make(map[string]struct{}, len(rfc9239JavaScriptMediaTypes))
	for _, alias := range rfc9239JavaScriptMediaTypes {
		want[alias] = struct{}{}
	}
	got := make(map[string]struct{}, len(media.JavaScriptMediaTypes))
	for _, alias := range media.JavaScriptMediaTypes {
		got[alias] = struct{}{}
	}

	for alias := range want {
		if _, ok := got[alias]; !ok {
			t.Errorf("media.JavaScriptMediaTypes is missing RFC 9239 JavaScript alias %q", alias)
		}
	}
	for alias := range got {
		if _, ok := want[alias]; !ok {
			t.Errorf("media.JavaScriptMediaTypes has unexpected JavaScript alias %q", alias)
		}
	}
}

// TestConfigTextualPassthroughTypeRefusesEveryJavaScriptAlias is the runtime
// counterpart of internal/config's load-time validation: the classifier that
// decides at REQUEST time whether a response's declared content type is
// "textual/scannable" (and so ineligible for an unscannable_passthrough
// match) must treat every RFC 9239 section 6 JavaScript alias as textual,
// not only the two that used to be spelled out in the switch. A response
// declaring "application/x-javascript" is equivalent JavaScript to one
// declaring "text/javascript", and both must remain on the normal scanned
// response path even though Browser Shield no longer edits their bytes.
func TestConfigTextualPassthroughTypeRefusesEveryJavaScriptAlias(t *testing.T) {
	for _, alias := range media.JavaScriptMediaTypes {
		if !configTextualPassthroughType(alias) {
			t.Errorf("configTextualPassthroughType(%q) = false, want true (RFC 9239 JavaScript alias)", alias)
		}
	}

	// Positive control: an actually-opaque type is NOT classified textual,
	// so the loop above is proving something about JavaScript specifically.
	if configTextualPassthroughType("application/octet-stream") {
		t.Fatal("configTextualPassthroughType(application/octet-stream) = true, want false")
	}
}

// TestMatchUnscannablePassthroughRefusesJavaScriptAliasResponse proves the
// refusal end to end at the runtime matcher: a response whose Content-Type is
// a JavaScript alias never matches an unscannable_passthrough entry, even one
// that (only reachable via a config file edited after validation, since
// config.Validate refuses this content type at load time) still names the
// alias in its content_types.
func TestMatchUnscannablePassthroughRefusesJavaScriptAliasResponse(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	for _, alias := range media.JavaScriptMediaTypes {
		entries := []config.UnscannablePassthroughEntry{{
			Host:         "*.example.com",
			Paths:        []string{"/artifacts/pkg.bin"},
			ContentTypes: []string{alias},
			Reason:       "opaque signed archive",
			Expires:      "2026-07-05",
		}}
		req := unscannablePassthroughRequest{
			Host:              "downloads.example.com",
			Path:              "/artifacts/pkg.bin",
			ContentType:       alias,
			Header:            http.Header{"Content-Disposition": []string{"attachment; filename=\"pkg.bin\""}},
			ContentLength:     4096,
			SizeExemptDomains: []string{"*.example.com"},
			Now:               now,
		}
		if _, ok := matchUnscannablePassthrough(req, entries); ok {
			t.Errorf("matchUnscannablePassthrough matched JavaScript alias %q as an opaque passthrough", alias)
		}
	}
}

func TestMatchUnscannablePassthroughRefusesParameterizedJavaScriptAliasResponse(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	for _, contentType := range []string{
		"application/javascript; charset=utf-8",
		"Application/JavaScript; Charset=UTF-8",
	} {
		t.Run(contentType, func(t *testing.T) {
			entries := []config.UnscannablePassthroughEntry{{
				Host:         "*.example.com",
				Paths:        []string{"/artifacts/pkg.bin"},
				ContentTypes: []string{"application/javascript"},
				Reason:       "opaque signed archive",
				Expires:      "2026-07-05",
			}}
			req := unscannablePassthroughRequest{
				Host:              "downloads.example.com",
				Path:              "/artifacts/pkg.bin",
				ContentType:       contentType,
				Header:            http.Header{"Content-Disposition": []string{"attachment; filename=\"pkg.bin\""}},
				ContentLength:     4096,
				SizeExemptDomains: []string{"*.example.com"},
				Now:               now,
			}
			if _, ok := matchUnscannablePassthrough(req, entries); ok {
				t.Errorf("matchUnscannablePassthrough matched parameterized JavaScript Content-Type %q as an opaque passthrough", contentType)
			}
		})
	}
}

// TestJavaScriptAliasTableConsumerAgreement catches a future consumer that
// stops calling the shared predicate and reintroduces a private alias list.
func TestJavaScriptAliasTableConsumerAgreement(t *testing.T) {
	for _, alias := range media.JavaScriptMediaTypes {
		runtimeSaysTextual := configTextualPassthroughType(alias)
		sharedTableSaysJS := media.IsJavaScriptMediaType(alias)
		if runtimeSaysTextual != sharedTableSaysJS {
			t.Errorf("alias %q: configTextualPassthroughType=%v but media.IsJavaScriptMediaType=%v, consumers disagree", alias, runtimeSaysTextual, sharedTableSaysJS)
		}
	}
}
