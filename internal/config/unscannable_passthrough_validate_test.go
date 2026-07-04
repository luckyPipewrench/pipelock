// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateUnscannablePassthroughRejectsInvalidEntries(t *testing.T) {
	validEntry := func() UnscannablePassthroughEntry {
		return UnscannablePassthroughEntry{
			Host:         "downloads.example.com",
			Paths:        []string{"/artifacts/pkg.bin"},
			ContentTypes: []string{"application/octet-stream"},
			Reason:       "opaque signed archive",
			Added:        "2026-07-04",
			Expires:      "2099-01-01",
		}
	}

	tests := []struct {
		name    string
		mutate  func(*UnscannablePassthroughEntry)
		wantErr string
	}{
		{
			name: "bad host",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Host = "https://downloads.example.com"
			},
			wantErr: "use a hostname pattern",
		},
		{
			name: "empty reason",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Reason = " \t "
			},
			wantErr: ".reason is required",
		},
		{
			name: "deprecated path prefix",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.PathPrefixes = []string{" "}
			},
			wantErr: ".path_prefixes is not supported",
		},
		{
			name: "empty paths",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = nil
			},
			wantErr: ".paths must contain at least one exact path",
		},
		{
			name: "empty path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{" "}
			},
			wantErr: ".paths[0] is empty",
		},
		{
			name: "relative path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"artifacts"}
			},
			wantErr: "must start with /",
		},
		{
			name: "bad path escape",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts/%zz"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "traversal path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts/../private"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "double encoded traversal path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts/%252e%252e/private"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "non canonical path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts//pkg"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "trailing slash path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts/pkg.bin/"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "root path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "encoded slash path",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts%2fpkg.bin"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "path parameter",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Paths = []string{"/artifacts/pkg.bin;download"}
			},
			wantErr: "must be an exact non-root canonical path",
		},
		{
			name: "empty content types",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.ContentTypes = nil
			},
			wantErr: ".content_types must contain at least one non-textual media type",
		},
		{
			name: "empty content type",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.ContentTypes = []string{" "}
			},
			wantErr: ".content_types[0] is empty",
		},
		{
			name: "invalid content type",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.ContentTypes = []string{"application/"}
			},
			wantErr: ".content_types[0]",
		},
		{
			name: "textual content type",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.ContentTypes = []string{"text/plain"}
			},
			wantErr: "textual/scannable",
		},
		{
			name: "missing expires",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Expires = " "
			},
			wantErr: ".expires is required",
		},
		{
			name: "invalid added date",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Added = "07/04/2026"
			},
			wantErr: ".added",
		},
		{
			name: "invalid expires date",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Expires = "07/04/2099"
			},
			wantErr: ".expires",
		},
		{
			name: "expired expires date",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Expires = "2000-01-01"
			},
			wantErr: "already expired",
		},
		{
			name: "reason control character",
			mutate: func(entry *UnscannablePassthroughEntry) {
				entry.Reason = "opaque\narchive"
			},
			wantErr: "control characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := validEntry()
			tt.mutate(&entry)
			cfg := Defaults()
			cfg.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{entry}

			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateUnscannablePassthroughNormalizesAcceptedValues(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SizeExemptDomains = []string{"downloads.example.com"}
	cfg.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{{
		Host:         " Downloads.Example.COM. ",
		Paths:        []string{" /artifacts/pkg.bin "},
		ContentTypes: []string{" Application/Octet-Stream; Charset=binary "},
		Reason:       " opaque signed archive ",
		Added:        " 2026-07-04 ",
		Expires:      " 2099-01-01 ",
	}}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}

	got := cfg.ResponseScanning.UnscannablePassthrough[0]
	if got.Host != "downloads.example.com" {
		t.Fatalf("host = %q, want normalized hostname", got.Host)
	}
	if got.Paths[0] != "/artifacts/pkg.bin" {
		t.Fatalf("path = %q, want trimmed exact path", got.Paths[0])
	}
	if got.ContentTypes[0] != "application/octet-stream" {
		t.Fatalf("content type = %q, want media type only", got.ContentTypes[0])
	}
	if got.Reason != "opaque signed archive" {
		t.Fatalf("reason = %q, want trimmed", got.Reason)
	}
	if got.Added != "2026-07-04" || got.Expires != "2099-01-01" {
		t.Fatalf("dates = %q/%q, want trimmed YYYY-MM-DD", got.Added, got.Expires)
	}
}

func TestValidateResponseScanningSizeExemptBoundsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "scan max bytes nonpositive",
			mutate: func(cfg *Config) {
				cfg.ResponseScanning.SizeExemptScanMaxBytes = 0
			},
			wantErr: "response_scanning.size_exempt_scan_max_bytes must be > 0",
		},
		{
			name: "inflight max bytes nonpositive",
			mutate: func(cfg *Config) {
				cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = 0
			},
			wantErr: "response_scanning.size_exempt_scan_max_inflight_bytes must be > 0",
		},
		{
			name: "inflight below scan max",
			mutate: func(cfg *Config) {
				cfg.ResponseScanning.SizeExemptScanMaxBytes = 100
				cfg.ResponseScanning.SizeExemptScanMaxInflightBytes = 50
			},
			wantErr: "response_scanning.size_exempt_scan_max_inflight_bytes must be >= response_scanning.size_exempt_scan_max_bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestCloneResponseScanningSizeExemptSlicesDoNotAlias(t *testing.T) {
	cfg := Defaults()
	cfg.ResponseScanning.SizeExemptDomains = []string{"downloads.example.com"}
	cfg.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{{
		Host:         "downloads.example.com",
		Paths:        []string{"/artifacts/pkg.bin"},
		PathPrefixes: []string{"/legacy"},
		ContentTypes: []string{"application/octet-stream"},
		Reason:       "opaque signed archive",
		Expires:      "2099-01-01",
	}}

	clone := cfg.Clone()
	clone.ResponseScanning.SizeExemptDomains[0] = "mutated.example.com"
	clone.ResponseScanning.UnscannablePassthrough[0].Paths[0] = "/mutated"
	clone.ResponseScanning.UnscannablePassthrough[0].PathPrefixes[0] = "/mutated-prefix"
	clone.ResponseScanning.UnscannablePassthrough[0].ContentTypes[0] = "text/plain"

	if got := cfg.ResponseScanning.SizeExemptDomains[0]; got != "downloads.example.com" {
		t.Fatalf("source size-exempt domain = %q, want no alias", got)
	}
	if got := cfg.ResponseScanning.UnscannablePassthrough[0].Paths[0]; got != "/artifacts/pkg.bin" {
		t.Fatalf("source path = %q, want no alias", got)
	}
	if got := cfg.ResponseScanning.UnscannablePassthrough[0].PathPrefixes[0]; got != "/legacy" {
		t.Fatalf("source path prefix = %q, want no alias", got)
	}
	if got := cfg.ResponseScanning.UnscannablePassthrough[0].ContentTypes[0]; got != "application/octet-stream" {
		t.Fatalf("source content type = %q, want no alias", got)
	}

	if got := cloneUnscannablePassthrough(nil); got != nil {
		t.Fatalf("cloneUnscannablePassthrough(nil) = %#v, want nil", got)
	}
}
