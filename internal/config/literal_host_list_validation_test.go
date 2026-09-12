// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestLiteralHostMatchLists_RefuseInertEntries covers the two host lists whose
// runtime matcher only folds case, and which until now had no validator at
// all. A malformed entry loaded clean and then matched no request, so the
// operator's pinned-certificate host was intercepted anyway while the config
// looked accepted. The failure direction is availability, so the repair
// refuses the input and canonicalizes the stored value; neither matcher is
// loosened.
func TestLiteralHostMatchLists_RefuseInertEntries(t *testing.T) {
	tests := []struct {
		name       string
		entry      string
		wantErr    string
		wantStored string
	}{
		{name: "exact host", entry: "vendor.example", wantStored: "vendor.example"},
		{name: "wildcard", entry: "*.vendor.example", wantStored: "*.vendor.example"},
		{name: "uppercase is folded to the matcher's view", entry: "Vendor.Example", wantStored: "vendor.example"},
		{name: "single root dot is canonicalized", entry: "vendor.example.", wantStored: "vendor.example"},
		{name: "double trailing dot", entry: "vendor.example..", wantErr: "must be written as"},
		// A DIFFERENT validator catches this one. The trailing-dot case above
		// normalizes to a valid host and is refused by the matcher-parity
		// check, so it never reaches the label grammar; an interior empty
		// label does, and nothing exercised that path through these lists.
		{name: "embedded empty label", entry: "vendor..example", wantErr: "empty DNS label"},
		{name: "leading dot", entry: ".vendor.example", wantErr: "empty DNS label"},
		{name: "leading space", entry: " vendor.example", wantErr: "must be written as"},
		{name: "empty", entry: "", wantErr: "empty"},
		{name: "embedded space", entry: "bad host", wantErr: "DNS label characters"},
		{name: "bare wildcard", entry: "*", wantErr: "only exact hosts"},
	}

	for _, tt := range tests {
		t.Run("passthrough/"+tt.name, func(t *testing.T) {
			cfg := Defaults()
			// Interception stays DISABLED on purpose. Enabling it makes
			// Validate require a CA certificate on disk, which a clean
			// runner does not have, and the list check runs ahead of the
			// enabled gate precisely so a config is checked before the
			// feature is switched on.
			cfg.TLSInterception.PassthroughDomains = []string{tt.entry}
			err := cfg.Validate()
			assertHostListOutcome(t, err, tt.wantErr,
				cfg.TLSInterception.PassthroughDomains[0], tt.wantStored)
		})

		t.Run("redirect_websocket_hosts/"+tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.WebSocketProxy.Enabled = true
			cfg.ForwardProxy.RedirectWebSocketHosts = []string{tt.entry}
			err := cfg.Validate()
			assertHostListOutcome(t, err, tt.wantErr,
				cfg.ForwardProxy.RedirectWebSocketHosts[0], tt.wantStored)
		})
	}
}

// TestLiteralHostMatchLists_ValidatedWhileDisabled pins that the lists are
// checked even when their feature is off. A config is edited and restarted
// later, so an entry accepted while the feature was disabled would become
// live without ever passing a check.
// TestLiteralHostMatchLists_BreadthPerList pins that breadth is judged for one
// list and not the other, because the two differ in what a wide wildcard costs.
//
// tls_interception.passthrough_domains splices a matching host without
// decrypting it, so "*.com" there turns body and response scanning off for
// every .com destination. That is the detector-off class this repository
// breadth-checks elsewhere, so the grant-list rule applies.
//
// forward_proxy.redirect_websocket_hosts routes matching hosts INTO the /ws
// proxy, which still scans them, so breadth there is a routing preference.
func TestLiteralHostMatchLists_BreadthPerList(t *testing.T) {
	t.Run("passthrough refuses a public-suffix wildcard", func(t *testing.T) {
		for _, entry := range []string{"*.com", "*.co.uk", "*.org"} {
			cfg := Defaults()
			cfg.TLSInterception.PassthroughDomains = []string{entry}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("passthrough accepted %q, which splices every host under that suffix", entry)
			}
			if !strings.Contains(err.Error(), "passthrough_domains") {
				t.Fatalf("error does not name the field: %v", err)
			}
		}
	})

	// Availability control, and the reason this is a per-list rule rather
	// than a blanket refusal. A private-suffix base and an ordinary vendor
	// wildcard are configuration an operator legitimately writes, including
	// the shipped default.
	t.Run("passthrough keeps the wildcards operators actually write", func(t *testing.T) {
		for _, entry := range []string{
			"*.googlevideo.com", "*.apple.com", "*.s3.amazonaws.com", "mtls.vendor.example",
		} {
			cfg := Defaults()
			cfg.TLSInterception.PassthroughDomains = []string{entry}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("passthrough refused the legitimate entry %q: %v", entry, err)
			}
		}
	})

	t.Run("shipped default survives", func(t *testing.T) {
		cfg := Defaults()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("the shipped default passthrough list is refused: %v", err)
		}
	})

	t.Run("redirect_websocket_hosts does not judge breadth", func(t *testing.T) {
		cfg := Defaults()
		cfg.ForwardProxy.RedirectWebSocketHosts = []string{"*.com"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("redirect_websocket_hosts wildcard refused: %v", err)
		}
	})
}

func TestLiteralHostMatchLists_ValidatedWhileDisabled(t *testing.T) {
	cfg := Defaults()
	cfg.TLSInterception.Enabled = false
	cfg.TLSInterception.PassthroughDomains = []string{"vendor.example.."}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a malformed passthrough entry was accepted while interception was disabled")
	}

	cfg = Defaults()
	cfg.ForwardProxy.Enabled = false
	cfg.ForwardProxy.RedirectWebSocketHosts = []string{"vendor.example.."}
	if err := cfg.Validate(); err == nil {
		t.Fatal("a malformed redirect host was accepted while the forward proxy was disabled")
	}
}

// TestDNSHostOverrides_RefuseEmptyLabelKey covers the same silent-inertness
// shape on the override map. The resolver's key normalizer removes ONE
// trailing dot, so a two-dot key was stored with a residual dot and no lookup
// ever matched it.
func TestDNSHostOverrides_RefuseEmptyLabelKey(t *testing.T) {
	tests := []struct {
		key     string
		wantErr bool
	}{
		{key: "pin.vendor.example"},
		{key: "pin.vendor.example."},
		{key: " pin.vendor.example"},
		{key: "pin.vendor.example..", wantErr: true},
		{key: "pin.vendor.example...", wantErr: true},
		{key: ".pin.vendor.example", wantErr: true},
		{key: "pin..vendor.example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			cfg := Defaults()
			cfg.DNS.HostOverrides = map[string][]string{tt.key: {"203.0.113.9"}}
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("key %q was accepted; it can never match a lookup", tt.key)
				}
				if !strings.Contains(err.Error(), "empty DNS label") {
					t.Fatalf("key %q error = %v, want an empty-label refusal", tt.key, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("key %q unexpectedly refused: %v", tt.key, err)
			}
		})
	}
}

func assertHostListOutcome(t *testing.T, err error, wantErr, stored, wantStored string) {
	t.Helper()
	if wantErr != "" {
		if err == nil {
			t.Fatalf("entry was accepted; want an error containing %q", wantErr)
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("error = %v, want it to contain %q", err, wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stored != wantStored {
		t.Fatalf("stored %q, want %q; the matcher compares this string verbatim", stored, wantStored)
	}
}
