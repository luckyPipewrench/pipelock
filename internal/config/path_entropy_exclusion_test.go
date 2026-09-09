// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// Validation exists because a path-entropy exclusion that cannot name a route
// is a host-wide or global exemption wearing a scoped name, and an operator
// would not see that reading the YAML. Every rejection below is one an operator
// could plausibly write by accident.
func TestValidatePathEntropyExclusions(t *testing.T) {
	t.Parallel()

	valid := PathEntropyExclusion{
		Host:       "docs.vendor.example",
		PathPrefix: "/document/d/",
		Reason:     "service-issued document identifier",
		Owner:      "platform",
		Expires:    "2027-01-01",
	}

	t.Run("control: a fully specified entry is accepted and normalized", func(t *testing.T) {
		t.Parallel()
		entries := []PathEntropyExclusion{{
			Host:       "  DOCS.Vendor.Example.  ",
			PathPrefix: "  /document/d/  ",
		}}
		if err := validatePathEntropyExclusions(entries); err != nil {
			t.Fatalf("validatePathEntropyExclusions(control) = %v, want nil", err)
		}
		if entries[0].Host != "docs.vendor.example" {
			t.Errorf("host = %q, want it lowercased and trailing-dot trimmed", entries[0].Host)
		}
		if entries[0].PathPrefix != "/document/d/" {
			t.Errorf("path_prefix = %q, want it trimmed", entries[0].PathPrefix)
		}
		if entries[0].Scheme != "https" {
			t.Errorf("scheme = %q, want https defaulted", entries[0].Scheme)
		}
	})

	tests := []struct {
		name    string
		entry   PathEntropyExclusion
		wantErr string
	}{
		{
			name:    "missing host would exempt every host",
			entry:   PathEntropyExclusion{PathPrefix: "/document/d/"},
			wantErr: "host is required",
		},
		{
			name:    "missing path prefix would exempt every path on the host",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example"},
			wantErr: "path_prefix is required",
		},
		{
			name:    "a root prefix exempts the whole host",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/"},
			wantErr: "exempts every path on the host",
		},
		{
			name:    "a relative prefix cannot match a normalized path",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "document/d/"},
			wantErr: "must start with /",
		},
		{
			name:    "a URL in the prefix field is a mistake, not a path",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "https://docs.vendor.example/document/d/"},
			wantErr: "must start with /",
		},
		{
			name:    "http is refused so an entry cannot silently cover cleartext",
			entry:   PathEntropyExclusion{Scheme: "http", Host: "docs.vendor.example", PathPrefix: "/document/d/"},
			wantErr: "must be https",
		},
		{
			name:    "an over-broad wildcard is refused",
			entry:   PathEntropyExclusion{Host: "*.example", PathPrefix: "/document/d/"},
			wantErr: "wildcard must target a concrete domain",
		},
		{
			name:    "a host:port is not a hostname",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example:443", PathPrefix: "/document/d/"},
			wantErr: "not a URL or host:port",
		},
		{
			name:    "an encoded slash cannot match an escaped request path",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document%2Fd/"},
			wantErr: "encoded slash or backslash",
		},
		{
			name:    "an encoded backslash is refused for the same reason",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document%5Cd/"},
			wantErr: "encoded slash or backslash",
		},
		{
			name:    "a query delimiter is not part of a path",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d?x=1"},
			wantErr: "query, fragment",
		},
		{
			name:    "a fragment delimiter is not part of a path",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d#frag"},
			wantErr: "query, fragment",
		},
		{
			name:    "a wildcard would widen the route silently",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/*/"},
			wantErr: "query, fragment",
		},
		{
			name:    "an encoded query delimiter is refused, not just a literal one",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document%3Fprivate/"},
			wantErr: "decoded path must not contain query, fragment",
		},
		{
			name:    "an encoded fragment delimiter is refused too",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document%23private/"},
			wantErr: "decoded path must not contain query, fragment",
		},
		{
			name:    "a dot segment is not the canonical route",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/./d/"},
			wantErr: "canonical",
		},
		{
			name:    "a traversal segment is refused",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d/../"},
			wantErr: "canonical",
		},
		{
			name:    "a backslash cannot stand in for a separator",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document\\d/"},
			wantErr: "query, fragment",
		},
		{
			name:    "a malformed expiry is refused rather than ignored",
			entry:   PathEntropyExclusion{Host: "docs.vendor.example", PathPrefix: "/document/d/", Expires: "soon"},
			wantErr: "must be YYYY-MM-DD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePathEntropyExclusions([]PathEntropyExclusion{tt.entry})
			if err == nil {
				t.Fatalf("validatePathEntropyExclusions(%+v) = nil, want an error", tt.entry)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}

	t.Run("a duplicate route is refused so two entries cannot disagree", func(t *testing.T) {
		t.Parallel()
		err := validatePathEntropyExclusions([]PathEntropyExclusion{valid, valid})
		if err == nil || !strings.Contains(err.Error(), "duplicates an earlier entry") {
			t.Fatalf("error = %v, want a duplicate rejection", err)
		}
	})

	t.Run("a wildcard host is accepted", func(t *testing.T) {
		t.Parallel()
		entries := []PathEntropyExclusion{{Host: "*.vendor.example", PathPrefix: "/document/d/"}}
		if err := validatePathEntropyExclusions(entries); err != nil {
			t.Fatalf("validatePathEntropyExclusions(wildcard) = %v, want nil", err)
		}
	})
}

// The field ships empty. That is what makes adding it behaviour-preserving, so
// it is worth pinning rather than assuming.
func TestPathEntropyExclusionsDefaultEmpty(t *testing.T) {
	t.Parallel()
	if got := Defaults().FetchProxy.Monitoring.PathEntropyExclusions; len(got) != 0 {
		t.Fatalf("default path_entropy_exclusions = %+v, want empty; a shipped default needs the vendor's published route contract behind it", got)
	}
}
