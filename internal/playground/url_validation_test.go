// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"strings"
	"testing"
)

func TestValidatePlainHTTPURL(t *testing.T) {
	credentialURL := "https://user:" + strings.ToLower("PASS") + "@model.api.test/v1"
	queryURL := "https://model.api.test/v1?api_key=" + strings.ToLower("SECRET")
	fragmentURL := "https://model.api.test/v1#" + strings.ToLower("SECRET")

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "http", raw: "http://model.api.test/v1"},
		{name: "https_with_port", raw: "https://model.api.test:8443/v1"},
		{name: "non_http_scheme", raw: "ftp://model.api.test/v1", wantErr: true},
		{name: "missing_host", raw: "http:///v1", wantErr: true},
		{name: "empty_hostname_with_port", raw: "http://:8080/v1", wantErr: true},
		{name: "credentials", raw: credentialURL, wantErr: true},
		{name: "query", raw: queryURL, wantErr: true},
		{name: "fragment", raw: fragmentURL, wantErr: true},
		{name: "unparseable", raw: "://bad\x00url", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ValidatePlainHTTPURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidatePlainHTTPURL: %v", err)
			}
			if u.Hostname() == "" {
				t.Fatalf("validated URL has empty hostname: %q", tc.raw)
			}
		})
	}
}
