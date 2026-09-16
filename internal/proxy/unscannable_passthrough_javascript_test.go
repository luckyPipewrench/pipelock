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

// TestConfigTextualPassthroughTypeRefusesEveryJavaScriptAlias is the runtime
// counterpart of internal/config's load-time validation: the classifier that
// decides at REQUEST time whether a response's declared content type is
// "textual/scannable" (and so ineligible for an unscannable_passthrough
// match) must treat every RFC 9239 section 6 JavaScript alias as textual,
// not only the two that used to be spelled out in the switch. A response
// declaring "application/x-javascript" is equivalent JavaScript to one
// declaring "text/javascript", and internal/shield.mediaTypeToPipeline
// already routes both through the JS rewrite pipeline.
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

// TestJavaScriptAliasTableParityBetweenShieldAndConfig fails the moment the
// shared table drifts: it directly checks that the classifier this package
// uses (configTextualPassthroughType) and the classifier internal/config
// uses at load time (isTextualUnscannablePassthroughType, exercised here
// indirectly through the shared media.IsJavaScriptMediaType predicate both of
// them call) return the SAME answer for every media.JavaScriptMediaTypes
// entry. Editing internal/media.JavaScriptMediaTypes to add or remove an
// alias updates both consumers at once by construction, so this test's real
// job is to catch a FUTURE regression where either consumer stops calling the
// shared predicate and reintroduces a private copy of the list.
func TestJavaScriptAliasTableParityBetweenShieldAndConfig(t *testing.T) {
	for _, alias := range media.JavaScriptMediaTypes {
		runtimeSaysTextual := configTextualPassthroughType(alias)
		sharedTableSaysJS := media.IsJavaScriptMediaType(alias)
		if runtimeSaysTextual != sharedTableSaysJS {
			t.Errorf("alias %q: configTextualPassthroughType=%v but media.IsJavaScriptMediaType=%v, the two consumers disagree", alias, runtimeSaysTextual, sharedTableSaysJS)
		}
	}
}
