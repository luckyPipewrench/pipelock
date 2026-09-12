// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"errors"
	"testing"
)

// TestNew_RejectsEmptyDNSLabel pins the empty-label refusal. Before it, the
// two request-side normalizers disagreed: this constructor and MatchDomain
// each remove ONE trailing dot, so "host.example.." reached a blocklist as
// "host.example." and matched nothing while reaching a strict allowlist as
// "host.example" and matched.
func TestNew_RejectsEmptyDNSLabel(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{name: "plain host", host: "vendor.example"},
		{name: "single root dot is a valid spelling", host: "vendor.example."},
		{name: "double trailing dot", host: "vendor.example..", wantErr: true},
		{name: "triple trailing dot", host: "vendor.example...", wantErr: true},
		{name: "leading dot", host: ".vendor.example", wantErr: true},
		{name: "interior empty label", host: "vendor..example", wantErr: true},
		{name: "ipv4 literal", host: "203.0.113.9"},
		{name: "ipv6 literal", host: "2001:db8::1"},
		{name: "ipv4 mapped ipv6", host: "::ffff:203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest, err := New(NetworkTCP, tt.host, 443)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New(%q) = %+v, want an error", tt.host, dest)
				}
				if !errors.Is(err, ErrInvalidHost) {
					t.Fatalf("New(%q) error = %v, want ErrInvalidHost", tt.host, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q) unexpected error: %v", tt.host, err)
			}
		})
	}
}
