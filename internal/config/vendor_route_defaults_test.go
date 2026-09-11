// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"context"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestVendorRouteDefaults pins BOTH directions of the shipped document-sharing
// route exclusions. The allow cases prove an operator sent an ordinary Google
// Docs, Sheets, Slides, Forms or Drive link is not blocked on a fresh install.
// The block cases are the ones that matter more: each shipped entry binds ONE
// host to ONE literal path prefix, so a different route on the same host, the
// same route shape on another host, and a lookalike host that merely carries
// the vendor host as a leading label must all still be blocked. Removing any
// entry makes its allow case fail with the real entropy reason, so neither
// direction is vacuous.
func TestVendorRouteDefaults(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	const id = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"
	const formID = "1FAIpQLSf1xQ2mGh7kVJd0pWqYxNzR3TbLcMnOpQrStUvWxYz012345"

	cases := []struct {
		name      string
		url       string
		wantAllow bool
	}{
		{"docs document", "https://docs.google.com/document/d/" + id + "/edit", true},
		{"docs spreadsheet", "https://docs.google.com/spreadsheets/d/" + id + "/edit", true},
		{"docs presentation", "https://docs.google.com/presentations/d/" + id + "/edit", true},
		{"docs form", "https://docs.google.com/forms/d/e/" + formID + "/viewform", true},
		{"drive file", "https://drive.google.com/file/d/" + id + "/view", true},

		// Must STILL block: same host, route not on the list.
		{"same host other route", "https://docs.google.com/random/" + id, false},
		// Must STILL block: listed route shape on an unlisted host.
		{"route on evil host", "https://evil.test/document/d/" + id, false},
		// Must STILL block: lookalike host with the vendor host as a prefix label.
		{"lookalike host", "https://docs.google.com.evil.test/document/d/" + id, false},
		// Must STILL block: listed prefix but the blob is elsewhere in the path.
		{"prefix then unrelated blob segment", "https://docs.google.com/random/d/" + id, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := sc.Scan(context.Background(), tc.url)
			if res.Allowed != tc.wantAllow {
				t.Fatalf("allowed=%v want %v (reason=%q scanner=%q)", res.Allowed, tc.wantAllow, res.Reason, res.Scanner)
			}
		})
	}
}
